"""Markdown outputs: analyst tickets for a triage run, and the evaluation report."""

from __future__ import annotations

from typing import Any

from alertlens.enrich import ATTACK
from alertlens.models import TriageResult, Verdict
from alertlens.playbooks import Library

BADGE = {
    Verdict.TRUE_POSITIVE: "🔴 true positive",
    Verdict.NEEDS_INVESTIGATION: "🟠 needs investigation",
    Verdict.FALSE_POSITIVE: "🟢 false positive",
}
ORDER = {Verdict.TRUE_POSITIVE: 0, Verdict.NEEDS_INVESTIGATION: 1, Verdict.FALSE_POSITIVE: 2}


def tickets(results: list[TriageResult], library: Library, include_closed: bool = False) -> str:
    shown = [r for r in results if include_closed or r.decision.verdict.escalated]
    shown.sort(key=lambda r: (ORDER[r.decision.verdict], -r.incident.size))
    closed = sum(not r.decision.verdict.escalated for r in results)
    lines = [
        "# Triage report",
        "",
        f"{len(results)} incidents triaged: {len(results) - closed} escalated, {closed} closed "
        "as false positives.",
        "",
    ]
    for r in shown:
        d, inc = r.decision, r.incident
        f = inc.facts()
        pb = library.get(r.playbook_id) if r.playbook_id else None
        lines += [
            f"## {inc.id} · {BADGE[d.verdict]} · severity {d.severity.value}",
            "",
            f"**{inc.family}** from `{inc.src_ip}` → {', '.join(f'`{ip}`' for ip in f['top_destinations'])} "  # noqa: E501
            f"· {inc.size} alert(s) · {f['first_seen']} · {f['duration_seconds']} s · triaged by `{r.triager}`",  # noqa: E501
            "",
            d.summary,
            "",
        ]
        if d.technique_ids:
            lines.append(
                "**ATT&CK:** " + ", ".join(f"{t} {ATTACK[t]['name']}" for t in d.technique_ids)
            )
            lines.append("")
        if d.action_step_ids and pb:
            lines.append(f"**Playbook {pb.id}, {pb.title}:**")
            lines += [f"- [ ] `{s}` {pb.steps[s]}" for s in d.action_step_ids]
            lines.append("")
        if f["most_unusual_features"]:
            lines.append("<sub>Evidence: " + "; ".join(f["most_unusual_features"]) + "</sub>")
            lines.append("")
    return "\n".join(lines) + "\n"


def _pct(x: float | None) -> str:
    return "–" if x is None else f"{100 * x:.0f}%"


def evaluation(m: dict[str, Any]) -> str:
    cfgs = m["configs"]
    lines = [
        "# AlertLens evaluation report",
        "",
        f"_Generated {m['generated_at']} with `{m['model']}` (Ollama, CPU)._",
        "",
        f"**Correlation:** {m['alerts']:,} alerts → {m['incidents']} incidents "
        f"({m['compression']:.0f}× fewer items to look at).",
        "",
        "**Rules on every incident:** "
        f"{_pct(m['rules_all_incidents']['escalation_recall'])} of attack incidents escalated, "
        f"{_pct(m['rules_all_incidents']['fp_closure_rate'])} of benign incidents closed.",
        "",
        f"## Stratified sample ({m['sample']['incidents']} incidents: every attack incident + "
        f"{m['sample']['n_benign']} random benign ones)",
        "",
        "| Triage | Attacks escalated | Attacks missed | Benign closed | Benign escalated | "
        "Mean latency |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    names = {
        "rules": "Rules only",
        "llm": "LLM decides",
        "hybrid": "Hybrid (rules decide, LLM explains)",
    }
    for key, label in names.items():
        c = cfgs[key]
        q = c["quality"]
        lines.append(
            f"| {label} | {_pct(c['escalation_recall'])} | {c['missed_attacks']} | "
            f"{_pct(c['fp_closure_rate'])} | {c['escalated_benign']} | {q['latency_s']['mean']:.1f} s |"  # noqa: E501
        )
    lines += [
        "",
        "![Triage comparison](figures/triage_comparison.png)",
        "",
        "## Grounding and faithfulness",
        "",
        "| Triage | Invalid outputs | Hallucinated step IDs | Hallucinated technique IDs | "
        "Summaries with unsupported claims | Steps cited per escalation |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for key in ("llm", "hybrid"):
        q = cfgs[key]["quality"]
        lines.append(
            f"| {names[key]} | {q['invalid_or_fallback']} | {q['hallucinated_step_ids']} | "
            f"{q['hallucinated_technique_ids']} | {q['summaries_with_unsupported_claims']} / "
            f"{cfgs[key]['incidents']} | {q['steps_cited_per_escalation']:.1f} |"
        )
    examples = cfgs["llm"]["quality"]["unsupported_claims_examples"]
    if examples:
        lines += [
            "",
            "Unsupported claims found in LLM-decides summaries: "
            + ", ".join(f"`{e}`" for e in examples),
        ]
    lines += [
        "",
        "## Escalations per detector family (LLM decides)",
        "",
        "| Family | Incidents | Attack incidents | Escalated |",
        "|---|---:|---:|---:|",
    ]
    for fam, row in sorted(cfgs["llm"]["per_family"].items()):
        lines.append(f"| {fam} | {row['incidents']} | {row['attacks']} | {row['escalated']} |")
    return "\n".join(lines) + "\n"
