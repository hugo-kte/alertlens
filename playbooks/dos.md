---
id: PB-DOS
title: Denial of service against a service
families: [DoS, DDoS]
techniques: [T1498, T1499]
---
## Triage
- [DOS-T1] Confirm user-visible impact: availability, latency and error rate of the targeted service.
- [DOS-T2] Count distinct sources: one source points to a DoS, many sources to a DDoS.
- [DOS-T3] Check whether the traffic pattern matches a known load test or a planned event.
## Containment
- [DOS-C1] Rate-limit or block the offending sources at the edge firewall or WAF.
- [DOS-C2] For volumetric floods, engage the upstream provider or DDoS scrubbing service.
- [DOS-C3] Scale out or enable caching for the targeted service while the event lasts.
## Recovery
- [DOS-R1] Lift temporary blocks gradually once traffic is back to baseline, watching error rates.
- [DOS-R2] Tune connection limits and timeouts on the targeted service (slow-request protection).
## Evidence
- [DOS-E1] Keep firewall/WAF logs and flow records for the whole incident window.
