---
id: PB-ANOM
title: Behavioural anomaly lead
families: [Anomaly]
techniques: []
---
## Triage
- [ANO-T1] Compare the flow with the host's usual activity: same peers, ports and volumes seen before?
- [ANO-T2] Check whether a known application or scheduled job explains the traffic.
- [ANO-T3] Look for corroborating signals: other alerts, authentication events, endpoint telemetry.
## Containment
- [ANO-C1] No containment for an isolated lead; escalate only if corroborated.
## Recovery
- [ANO-R1] If benign, record the explanation so that similar leads can be closed faster.
## Evidence
- [ANO-E1] Keep the flow record and the anomaly score in the case notes.
