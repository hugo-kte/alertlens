"""Triage: a rules baseline and an LLM triager grounded in the retrieved playbook."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from pydantic import ValidationError

from alertlens.enrich import ATTACK, Context
from alertlens.llm import ChatModel
from alertlens.models import (
    Explanation,
    Incident,
    Severity,
    TriageDecision,
    TriageResult,
    Verdict,
)
from alertlens.playbooks import Library, Playbook

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a tier-1 SOC analyst assistant. You triage incidents built by \
correlating network intrusion-detection alerts (same source, same detector family, close in \
time). For each incident decide:
- "true_positive": malicious activity that needs a response,
- "false_positive": benign activity that can be closed,
- "needs_investigation": the evidence is not enough to decide.

Weigh the evidence like an analyst: agreement between the supervised classifier and the \
anomaly detector, the number of alerts and how many hosts and ports they touch, the attack \
probability, whether the source is internal or external, and the criticality of the targets. \
An isolated alert raised only by the anomaly detector is often benign.

Rules:
- Cite only action step IDs that appear in the playbook given with the incident.
- Cite only technique IDs from the allowed list.
- Summary: at most three factual sentences an analyst can paste into a ticket.
- Answer with JSON only."""


_STEP_ID = re.compile(r"^\s*`?([A-Z0-9]+-[A-Z]\d+)\b")


def normalise_steps(ids: list[str]) -> list[str]:
    """Accept 'DOS-C1: Rate-limit...' (a common small-model habit) as 'DOS-C1'."""
    out = []
    for raw in ids:
        m = _STEP_ID.match(raw)
        step = m.group(1) if m else raw
        if step not in out:
            out.append(step)
    return out


def schema() -> dict[str, Any]:
    return TriageDecision.model_json_schema()


def build_prompt(facts: dict[str, Any], playbook: Playbook) -> str:
    allowed = {tid: v["name"] for tid, v in ATTACK.items()}
    return (
        "Incident:\n"
        + json.dumps(facts, indent=1, default=str)
        + "\n\nPlaybook (cite step IDs):\n"
        + playbook.render()
        + "\n\nAllowed technique IDs:\n"
        + json.dumps(allowed)
    )


def rules_decision(incident: Incident, playbook: Playbook) -> TriageDecision:
    """Transparent baseline, written before looking at any result."""
    f = incident.facts()
    det = f["detectors"]
    both, supervised = det.get("both", 0), det.get("supervised", 0)
    if both > 0 or supervised >= 5:
        verdict, severity = Verdict.TRUE_POSITIVE, Severity.HIGH
    elif supervised > 0 or incident.size >= 5:
        verdict, severity = Verdict.NEEDS_INVESTIGATION, Severity.MEDIUM
    else:
        verdict, severity = Verdict.FALSE_POSITIVE, Severity.LOW
    return TriageDecision(
        verdict=verdict,
        confidence=0.5,
        severity=severity,
        summary=f"{incident.size} {incident.family} alert(s) from {incident.src_ip}.",
        technique_ids=f["technique_ids"][:5],
        # escalations start with the playbook's triage steps
        action_step_ids=next(iter(playbook.sections.values()), []) if verdict.escalated else [],
        rationale=f"detectors={det}",
    )


class Triager:
    def __init__(self, model: ChatModel | None, library: Library, context: Context) -> None:
        self.model = model
        self.library = library
        self.context = context

    def rules(self, incident: Incident) -> TriageResult:
        t0 = time.perf_counter()
        pb = self.library.retrieve(incident.family, incident.facts()["technique_ids"])
        return TriageResult(
            incident,
            rules_decision(incident, pb),
            "rules",
            pb.id,
            latency_s=time.perf_counter() - t0,
        )

    def llm(self, incident: Incident, retries: int = 1) -> TriageResult:
        if self.model is None:
            raise ValueError("no model configured")
        facts = incident.facts()
        playbook = self.library.retrieve(incident.family, facts["technique_ids"])
        prompt = build_prompt(self.context.enrich(facts), playbook)
        t0 = time.perf_counter()
        error = None
        for attempt in range(1, retries + 2):
            raw = self.model.complete(
                SYSTEM_PROMPT,
                prompt
                if error is None
                else f"{prompt}\n\nYour previous answer was invalid: {error}",
                schema(),
            )
            try:
                decision = TriageDecision.model_validate_json(raw)
            except ValidationError as exc:
                error = str(exc.errors()[0]["msg"])
                log.warning("%s: invalid output (%s), attempt %d", incident.id, error, attempt)
                continue
            decision.action_step_ids = normalise_steps(decision.action_step_ids)
            bad_steps = [s for s in decision.action_step_ids if s not in playbook.steps]
            bad_techniques = [t for t in decision.technique_ids if t not in ATTACK]
            decision.action_step_ids = [s for s in decision.action_step_ids if s in playbook.steps]
            decision.technique_ids = [t for t in decision.technique_ids if t in ATTACK]
            return TriageResult(
                incident,
                decision,
                f"llm:{self.model.name}",
                playbook.id,
                hallucinated_steps=bad_steps,
                hallucinated_techniques=bad_techniques,
                latency_s=time.perf_counter() - t0,
                attempts=attempt,
            )
        fallback = self.rules(incident)
        fallback.triager, fallback.attempts = "llm-fallback", retries + 1
        fallback.latency_s = time.perf_counter() - t0
        return fallback


HYBRID_PROMPT = """You are a tier-1 SOC analyst assistant. The incident below has already been \
classified by deterministic detection rules; do not change the verdict. Write the ticket summary \
(at most three factual sentences, only facts present in the incident), cite the relevant \
technique IDs from the allowed list, and pick the playbook steps to run, by ID. Answer with JSON \
only."""


def explain(triager: Triager, incident: Incident) -> TriageResult:
    """Hybrid mode: rules decide, the model writes the summary and selects the steps."""
    base = triager.rules(incident)
    if triager.model is None:
        return base
    facts = incident.facts()
    playbook = triager.library.get(base.playbook_id)
    prompt = (
        f"Verdict (fixed): {base.decision.verdict.value}, severity "
        f"{base.decision.severity.value}\n\n"
        + build_prompt(triager.context.enrich(facts), playbook)
    )
    t0 = time.perf_counter()
    for attempt in (1, 2):
        raw = triager.model.complete(HYBRID_PROMPT, prompt, Explanation.model_json_schema())
        try:
            exp = Explanation.model_validate_json(raw)
        except ValidationError:
            continue
        exp.action_step_ids = normalise_steps(exp.action_step_ids)
        bad_steps = [x for x in exp.action_step_ids if x not in playbook.steps]
        bad_tech = [t for t in exp.technique_ids if t not in ATTACK]
        decision = base.decision.model_copy(
            update={
                "summary": exp.summary,
                "technique_ids": [t for t in exp.technique_ids if t in ATTACK],
                "action_step_ids": [x for x in exp.action_step_ids if x in playbook.steps]
                or base.decision.action_step_ids,
            }
        )
        return TriageResult(
            incident,
            decision,
            f"hybrid:{triager.model.name}",
            playbook.id,
            bad_steps,
            bad_tech,
            time.perf_counter() - t0,
            attempt,
        )
    return base
