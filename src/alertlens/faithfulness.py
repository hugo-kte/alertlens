"""Automatic faithfulness check for model-written summaries.

A summary is pasted into tickets and read by people who will act on it, so every concrete
claim it makes must be traceable to the incident facts. This checker extracts the claims that
can be verified mechanically (IP addresses, asset names, ATT&CK technique IDs and names) and
reports those the facts do not support. It cannot judge free-form reasoning, so it gives a
lower bound on hallucinations, not a proof of correctness.
"""

from __future__ import annotations

import re
from typing import Any

from alertlens.enrich import ATTACK

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def unsupported_claims(summary: str, facts: dict[str, Any], asset_names: set[str]) -> list[str]:
    """Claims in ``summary`` not backed by ``facts`` (the enriched incident given to the model)."""
    issues: list[str] = []
    known_ips = {facts["source"]["ip"], *(d["ip"] for d in facts["destinations"])}
    for ip in _IP.findall(summary):
        if ip not in known_ips:
            issues.append(f"ip:{ip}")
    known_names = {facts["source"].get("name"), *(d.get("name") for d in facts["destinations"])}
    lowered = summary.lower()
    for name in asset_names:
        if re.search(rf"\b{re.escape(name.lower())}\b", lowered) and name not in known_names:
            issues.append(f"asset:{name}")
    known_techniques = {t["id"] for t in facts.get("techniques", [])}
    for tid in _TID.findall(summary):
        if tid.split(".")[0] not in known_techniques:
            issues.append(f"technique:{tid}")
    for tid, meta in ATTACK.items():
        if meta["name"].lower() in lowered and tid not in known_techniques:
            issues.append(f"technique_name:{meta['name']}")
    return issues
