"""Data model: alerts in, incidents in the middle, triage decisions out."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


@dataclass(frozen=True)
class Alert:
    ts: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    transport: str
    family: str  # detector's label: DoS, PortScan, Anomaly...
    detector: str  # supervised | anomaly | both
    severity: int  # 0-100 (ECS event.severity)
    technique_id: str | None = None
    attack_probability: float | None = None
    anomaly_ratio: float | None = None
    explanation: tuple[str, ...] = ()
    # Evaluation only: never shown to the model.
    ground_truth: str | None = None


@dataclass
class Incident:
    id: str
    src_ip: str
    family: str
    alerts: list[Alert] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime:
        return self.alerts[0].ts

    @property
    def last_seen(self) -> datetime:
        return self.alerts[-1].ts

    @property
    def size(self) -> int:
        return len(self.alerts)

    def facts(self) -> dict[str, Any]:
        """What an analyst (or the model) sees: aggregates, no ground truth."""
        detectors = Counter(a.detector for a in self.alerts)
        probs = [a.attack_probability for a in self.alerts if a.attack_probability is not None]
        ratios = [a.anomaly_ratio for a in self.alerts if a.anomaly_ratio is not None]
        dsts = Counter(a.dst_ip for a in self.alerts)
        ports = Counter(a.dst_port for a in self.alerts)
        span = (self.last_seen - self.first_seen).total_seconds()
        explanations = Counter(e for a in self.alerts for e in a.explanation[:1])
        return {
            "incident_id": self.id,
            "source_ip": self.src_ip,
            "detector_family": self.family,
            "alerts": self.size,
            "first_seen": self.first_seen.isoformat(timespec="seconds"),
            "duration_seconds": round(span),
            "distinct_destinations": len(dsts),
            "top_destinations": [ip for ip, _ in dsts.most_common(3)],
            "distinct_destination_ports": len(ports),
            "top_destination_ports": [p for p, _ in ports.most_common(5)],
            "transport": sorted({a.transport for a in self.alerts}),
            "detectors": dict(detectors),
            "max_attack_probability": round(max(probs), 3) if probs else None,
            "max_anomaly_ratio": round(max(ratios), 2) if ratios else None,
            "max_severity": max(a.severity for a in self.alerts),
            "technique_ids": sorted({a.technique_id for a in self.alerts if a.technique_id}),
            "most_unusual_features": [e for e, _ in explanations.most_common(3)],
        }

    @property
    def truth(self) -> str | None:
        """Majority ground truth: 'attack' or 'benign' (None if unlabelled)."""
        labels = [a.ground_truth for a in self.alerts if a.ground_truth is not None]
        if not labels:
            return None
        attacks = sum(label != "BENIGN" for label in labels)
        return "attack" if attacks * 2 >= len(labels) else "benign"


class Verdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_INVESTIGATION = "needs_investigation"

    @property
    def escalated(self) -> bool:
        return self is not Verdict.FALSE_POSITIVE


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TriageDecision(BaseModel):
    """Structured output the model must produce (enforced with a JSON schema)."""

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    summary: str = Field(max_length=600)
    technique_ids: list[str] = Field(default_factory=list, max_length=5)
    action_step_ids: list[str] = Field(default_factory=list, max_length=8)
    rationale: str = Field(max_length=600)

    @model_validator(mode="after")
    def _escalations_need_actions(self) -> TriageDecision:
        if self.verdict.escalated and not self.action_step_ids:
            raise ValueError("an escalated incident must cite at least one playbook step")
        return self


class Explanation(BaseModel):
    """Hybrid mode: the verdict comes from the rules, the model only explains and plans."""

    summary: str = Field(max_length=600)
    technique_ids: list[str] = Field(default_factory=list, max_length=5)
    action_step_ids: list[str] = Field(min_length=1, max_length=8)


@dataclass
class TriageResult:
    incident: Incident
    decision: TriageDecision
    triager: str  # "llm:<model>" | "rules" | "llm-fallback"
    playbook_id: str | None = None
    hallucinated_steps: list[str] = field(default_factory=list)
    hallucinated_techniques: list[str] = field(default_factory=list)
    latency_s: float = 0.0
    attempts: int = 1
