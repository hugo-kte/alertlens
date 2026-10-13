"""Alert ingestion: ECS-style JSON (FlowGuard) and Suricata EVE alerts -> :class:`Alert`."""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from alertlens.models import Alert

# Suricata/ET rule categories -> detector family (best effort, extend as needed)
EVE_CATEGORIES = {
    "Attempted Denial of Service": "DoS",
    "Detection of a Network Scan": "PortScan",
    "Attempted Information Leak": "PortScan",
    "Attempted Administrator Privilege Gain": "WebAttack",
    "Web Application Attack": "WebAttack",
    "A Network Trojan was detected": "Botnet",
    "Malware Command and Control Activity Detected": "Botnet",
    "Attempted User Privilege Gain": "BruteForce",
}


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def from_ecs(doc: dict[str, Any]) -> Alert:
    fg = doc.get("flowguard", {})
    technique = (doc.get("threat") or {}).get("technique") or {}
    return Alert(
        ts=_ts(doc["@timestamp"]),
        src_ip=doc["source"]["ip"],
        dst_ip=doc["destination"]["ip"],
        dst_port=int(doc["destination"].get("port", -1)),
        transport=(doc.get("network") or {}).get("transport", "unknown"),
        family=fg.get("family") or (doc.get("rule") or {}).get("name", "unknown"),
        detector=fg.get("detector", "rule"),
        severity=int((doc.get("event") or {}).get("severity", 47)),
        technique_id=technique.get("id"),
        attack_probability=fg.get("attack_probability"),
        anomaly_ratio=fg.get("anomaly_ratio"),
        explanation=tuple(fg.get("explanation") or ()),
        ground_truth=fg.get("ground_truth"),
    )


def from_eve(doc: dict[str, Any]) -> Alert:
    alert = doc["alert"]
    severity = {1: 90, 2: 70, 3: 40}.get(int(alert.get("severity", 3)), 40)
    return Alert(
        ts=_ts(doc["timestamp"]),
        src_ip=doc["src_ip"],
        dst_ip=doc["dest_ip"],
        dst_port=int(doc.get("dest_port", -1)),
        transport=str(doc.get("proto", "unknown")).lower(),
        family=EVE_CATEGORIES.get(alert.get("category", ""), "Other"),
        detector="signature",
        severity=severity,
    )


def parse(doc: dict[str, Any]) -> Alert | None:
    if doc.get("event_type") == "alert" and "alert" in doc:
        return from_eve(doc)
    if "@timestamp" in doc and "source" in doc:
        return from_ecs(doc)
    return None


def read_alerts(path: str | Path) -> list[Alert]:
    """Read JSONL (optionally gzipped), skipping lines that are not alerts."""
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as fh:
        alerts = [a for a in (parse(json.loads(line)) for line in fh if line.strip()) if a]
    return sorted(alerts, key=lambda a: a.ts)


def iter_raw(path: str | Path) -> Iterator[dict[str, Any]]:
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)
