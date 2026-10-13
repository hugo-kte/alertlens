"""Deterministic context: asset inventory, network scope and an ATT&CK reference.

Only facts a defender knows in advance are used (their own assets and networks). Nothing here
looks at the alert's ground truth, so enrichment cannot leak the answer to the model.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# Compact ATT&CK reference for the techniques the detectors can emit (descriptions are ours).
ATTACK: dict[str, dict[str, str]] = {
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Enumerating services listening on remote hosts, e.g. port scans.",
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Probing victim infrastructure from outside before an intrusion.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Repeated authentication attempts to guess valid credentials.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploiting a weakness in an internet-facing service or web application.",
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Exhausting network bandwidth or capacity to degrade availability.",
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Exhausting a service or host's resources to degrade availability.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Command-and-control traffic blended into common protocols such as HTTP.",
    },
}


@dataclass(frozen=True)
class Asset:
    ip: str
    name: str
    role: str
    criticality: str
    internet_facing: bool = False


class Context:
    def __init__(self, assets: list[Asset], internal_networks: list[str]) -> None:
        self.assets = {a.ip: a for a in assets}
        self.networks = [ipaddress.ip_network(n) for n in internal_networks]

    @classmethod
    def load(cls, path: str | Path) -> Context:
        data = yaml.safe_load(Path(path).read_text())
        assets = [Asset(**a) for a in data.get("assets", [])]
        return cls(assets, data.get("internal_networks", []))

    def scope(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"
        return "internal" if any(addr in n for n in self.networks) else "external"

    def describe(self, ip: str) -> dict[str, Any]:
        out: dict[str, Any] = {"ip": ip, "scope": self.scope(ip)}
        asset = self.assets.get(ip)
        if asset:
            out |= {
                "name": asset.name,
                "role": asset.role,
                "criticality": asset.criticality,
                "internet_facing": asset.internet_facing,
            }
        return out

    def enrich(self, facts: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(facts)
        enriched["source"] = self.describe(facts["source_ip"])
        enriched["destinations"] = [self.describe(ip) for ip in facts["top_destinations"]]
        enriched["techniques"] = [
            {"id": t, **ATTACK[t]} for t in facts.get("technique_ids", []) if t in ATTACK
        ]
        for key in ("source_ip", "top_destinations", "technique_ids"):
            enriched.pop(key, None)
        return enriched
