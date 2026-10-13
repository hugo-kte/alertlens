---
id: PB-SCAN
title: Network scanning and service discovery
families: [PortScan]
techniques: [T1046, T1595]
---
## Triage
- [SCN-T1] Determine whether the scanner is internal (possible compromised host) or external (reconnaissance).
- [SCN-T2] Check if the source is an authorised vulnerability scanner or asset inventory tool.
- [SCN-T3] List the ports and hosts probed and which services answered.
## Containment
- [SCN-C1] For an external source, block it at the edge and watch for follow-up exploitation attempts.
- [SCN-C2] For an internal source, isolate the host and open a host investigation.
## Recovery
- [SCN-R1] Close or firewall the services that answered but do not need to be exposed.
## Evidence
- [SCN-E1] Keep flow records showing the probed ports and responses.
