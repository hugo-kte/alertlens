"""Alert correlation: group alerts that tell the same story into one incident.

Two alerts belong to the same incident when they share a source and a detector family and
are separated by less than ``gap`` (a session-window grouping). Grouping by source matches how
an analyst works ("what is this host doing?"), and the gap keeps unrelated bursts apart.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta

from alertlens.models import Alert, Incident


def correlate(alerts: Iterable[Alert], gap: timedelta = timedelta(minutes=30)) -> list[Incident]:
    open_incidents: dict[tuple[str, str], Incident] = {}
    incidents: list[Incident] = []
    for alert in sorted(alerts, key=lambda a: a.ts):
        key = (alert.src_ip, alert.family)
        current = open_incidents.get(key)
        if current is None or alert.ts - current.last_seen > gap:
            current = Incident(
                id=f"INC-{len(incidents) + 1:04d}", src_ip=alert.src_ip, family=alert.family
            )
            incidents.append(current)
            open_incidents[key] = current
        current.alerts.append(alert)
    return incidents
