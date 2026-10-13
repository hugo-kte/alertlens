"""Evaluation against ground truth: does the model triage better than transparent rules?

The FlowGuard replay carries the CICIDS2017 label of every alert, so every incident has a
known answer (majority label). A SOC cares about two numbers:

* **escalation recall**: share of real attacks that reach an analyst (missed = worst case);
* **false-positive closure**: share of benign incidents closed automatically (analyst time saved).

Rules run on every incident. The model is slow on a laptop CPU, so it runs on a stratified
sample: every attack incident plus a seeded random sample of benign ones.
"""

from __future__ import annotations

import json
import logging
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from alertlens.correlate import correlate
from alertlens.enrich import Context
from alertlens.faithfulness import unsupported_claims
from alertlens.ingest import read_alerts
from alertlens.llm import ChatModel
from alertlens.models import Incident, TriageResult
from alertlens.playbooks import Library
from alertlens.triage import Triager, explain

log = logging.getLogger(__name__)


def stratified_sample(incidents: list[Incident], n_benign: int, seed: int = 0) -> list[Incident]:
    attacks = [i for i in incidents if i.truth == "attack"]
    benign = [i for i in incidents if i.truth == "benign"]
    rng = random.Random(seed)
    return sorted(attacks + rng.sample(benign, min(n_benign, len(benign))), key=lambda i: i.id)


def verdict_metrics(results: list[TriageResult]) -> dict[str, Any]:
    attacks = [r for r in results if r.incident.truth == "attack"]
    benign = [r for r in results if r.incident.truth == "benign"]
    escalated_attacks = sum(r.decision.verdict.escalated for r in attacks)
    closed_benign = sum(not r.decision.verdict.escalated for r in benign)
    return {
        "incidents": len(results),
        "attack_incidents": len(attacks),
        "benign_incidents": len(benign),
        "escalation_recall": escalated_attacks / len(attacks) if attacks else None,
        "missed_attacks": len(attacks) - escalated_attacks,
        "fp_closure_rate": closed_benign / len(benign) if benign else None,
        "escalated_benign": len(benign) - closed_benign,
        "verdicts": {
            v: sum(r.decision.verdict.value == v for r in results)
            for v in ("true_positive", "false_positive", "needs_investigation")
        },
    }


def quality_metrics(results: list[TriageResult], context: Context) -> dict[str, Any]:
    names = {a.name for a in context.assets.values()}
    unsupported = [
        unsupported_claims(r.decision.summary, context.enrich(r.incident.facts()), names)
        for r in results
    ]
    latencies = np.array([r.latency_s for r in results])
    return {
        "invalid_or_fallback": sum(r.triager.endswith("fallback") for r in results),
        "retries": sum(r.attempts > 1 for r in results),
        "hallucinated_step_ids": sum(len(r.hallucinated_steps) for r in results),
        "hallucinated_technique_ids": sum(len(r.hallucinated_techniques) for r in results),
        "summaries_with_unsupported_claims": sum(bool(u) for u in unsupported),
        "unsupported_claims_examples": sorted({c for u in unsupported for c in u})[:12],
        "steps_cited_per_escalation": float(
            np.mean(
                [len(r.decision.action_step_ids) for r in results if r.decision.verdict.escalated]
                or [0]
            )
        ),
        "latency_s": {"mean": float(latencies.mean()), "p95": float(np.percentile(latencies, 95))},
    }


def per_family(results: list[TriageResult]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for r in results:
        row = out.setdefault(r.incident.family, {"incidents": 0, "attacks": 0, "escalated": 0})
        row["incidents"] += 1
        row["attacks"] += r.incident.truth == "attack"
        row["escalated"] += r.decision.verdict.escalated
    return out


def run(
    alerts_path: Path,
    model: ChatModel,
    playbooks: Path = Path("playbooks"),
    assets: Path = Path("configs/assets.yaml"),
    n_benign: int = 40,
    out_dir: Path = Path("reports"),
    seed: int = 0,
) -> dict[str, Any]:
    alerts = read_alerts(alerts_path)
    incidents = correlate(alerts)
    context = Context.load(assets)
    triager = Triager(model, Library.load(playbooks), context)
    sample = stratified_sample(incidents, n_benign, seed)
    log.info(
        "%d alerts -> %d incidents; evaluating the model on %d",
        len(alerts),
        len(incidents),
        len(sample),
    )

    rules_all = [triager.rules(i) for i in incidents]
    configs: dict[str, list[TriageResult]] = {"rules": [triager.rules(i) for i in sample]}
    configs["llm"] = []
    for k, inc in enumerate(sample, 1):
        configs["llm"].append(triager.llm(inc))
        log.info("llm %d/%d %s -> %s", k, len(sample), inc.id, configs["llm"][-1].decision.verdict)
    configs["hybrid"] = []
    for k, inc in enumerate(sample, 1):
        configs["hybrid"].append(explain(triager, inc))
        log.info("hybrid %d/%d %s", k, len(sample), inc.id)

    metrics: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "model": model.name,
        "alerts": len(alerts),
        "incidents": len(incidents),
        "compression": len(alerts) / max(len(incidents), 1),
        "rules_all_incidents": verdict_metrics(rules_all),
        "sample": {"incidents": len(sample), "seed": seed, "n_benign": n_benign},
        "configs": {
            name: verdict_metrics(res)
            | {"quality": quality_metrics(res, context), "per_family": per_family(res)}
            for name, res in configs.items()
        },
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2, default=str))
    with (out_dir / "triage_results.jsonl").open("w", encoding="utf-8") as fh:
        for name, res in configs.items():
            for r in res:
                fh.write(
                    json.dumps(
                        {
                            "config": name,
                            "incident": r.incident.id,
                            "family": r.incident.family,
                            "alerts": r.incident.size,
                            "truth": r.incident.truth,
                            "triager": r.triager,
                            "playbook": r.playbook_id,
                            "decision": r.decision.model_dump(mode="json"),
                            "hallucinated_steps": r.hallucinated_steps,
                            "latency_s": round(r.latency_s, 2),
                        }
                    )
                    + "\n"
                )
    return metrics
