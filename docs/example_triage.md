# Triage report

8 incidents triaged: 8 escalated, 0 closed as false positives.

## INC-0107 · 🔴 true positive · severity high

**DoS** from `172.16.0.1` → `192.168.10.50` · 4032 alert(s) · 2017-07-05T12:48:54+00:00 · 5455 s · triaged by `hybrid:llama3.2:3b`

High-severity DoS incident detected on internal service, matching T1499 technique ID.

**Playbook PB-DOS, Denial of service against a service:**
- [ ] `DOS-T1` Confirm user-visible impact: availability, latency and error rate of the targeted service.
- [ ] `DOS-T2` Count distinct sources: one source points to a DoS, many sources to a DDoS.
- [ ] `DOS-T3` Check whether the traffic pattern matches a known load test or a planned event.
- [ ] `DOS-C1` Rate-limit or block the offending sources at the edge firewall or WAF.
- [ ] `DOS-C2` For volumetric floods, engage the upstream provider or DDoS scrubbing service.
- [ ] `DOS-C3` Scale out or enable caching for the targeted service while the event lasts.
- [ ] `DOS-R1` Lift temporary blocks gradually once traffic is back to baseline, watching error rates.
- [ ] `DOS-R2` Tune connection limits and timeouts on the targeted service (slow-request protection).

<sub>Evidence: packets sent by the responder = 6; flow iat min = 0; fwd iat min = 1</sub>

## INC-0235 · 🔴 true positive · severity high

**DDoS** from `172.16.0.1` → `192.168.10.50` · 2210 alert(s) · 2017-07-07T18:56:33+00:00 · 1177 s · triaged by `hybrid:llama3.2:3b`

DDoS incident detected, high severity, confirmed by deterministic detection rules

**Playbook PB-DOS, Denial of service against a service:**
- [ ] `DOS-T1` Confirm user-visible impact: availability, latency and error rate of the targeted service.
- [ ] `DOS-T2` Count distinct sources: one source points to a DoS, many sources to a DDoS.
- [ ] `DOS-T3` Check whether the traffic pattern matches a known load test or a planned event.
- [ ] `DOS-C1` Rate-limit or block the offending sources at the edge firewall or WAF.
- [ ] `DOS-C2` For volumetric floods, engage the upstream provider or DDoS scrubbing service.
- [ ] `DOS-C3` Scale out or enable caching for the targeted service while the event lasts.
- [ ] `DOS-R1` Lift temporary blocks gradually once traffic is back to baseline, watching error rates.
- [ ] `DOS-R2` Tune connection limits and timeouts on the targeted service (slow-request protection).

<sub>Evidence: idle max = 0; idle min = 0; largest payload (B) = 10,135</sub>

## INC-0174 · 🔴 true positive · severity high

**PortScan** from `192.168.10.8` → `192.168.10.9`, `192.168.10.16`, `192.168.10.25` · 126 alert(s) · 2017-07-06T17:37:56+00:00 · 4052 s · triaged by `hybrid:llama3.2:3b`

PortScan detector detected high-severity incident with 126 alerts, indicating network service discovery (T1046) and potential reconnaissance activity.

**Playbook PB-SCAN, Network scanning and service discovery:**
- [ ] `SCN-T1` Determine whether the scanner is internal (possible compromised host) or external (reconnaissance).
- [ ] `SCN-T2` Check if the source is an authorised vulnerability scanner or asset inventory tool.
- [ ] `SCN-T3` List the ports and hosts probed and which services answered.

<sub>Evidence: payload throughput (B/s) = 0; SYN flags = 4; fwd iat mean = 3</sub>

## INC-0051 · 🔴 true positive · severity high

**BruteForce** from `172.16.0.1` → `192.168.10.50` · 97 alert(s) · 2017-07-04T12:20:48+00:00 · 3456 s · triaged by `hybrid:llama3.2:3b`

Repeated authentication attempts to guess valid credentials against a public web server (Ubuntu 16, Apache) from an internal edge firewall.

**ATT&CK:** T1110 Brute Force

**Playbook PB-BRUTE, Password guessing against an authentication service:**
- [ ] `BRU-T1` Check authentication logs on the target for failed and successful logins from the source.
- [ ] `BRU-T2` Identify the targeted accounts and whether any login succeeded during or after the burst.
- [ ] `BRU-T3` Check whether the source is an internal tool (monitoring, backup) with a stale password.
- [ ] `BRU-C1` Block the source address at the firewall for the targeted service.
- [ ] `BRU-C2` If a login succeeded, disable the account, revoke its sessions and keys, and reset the password.
- [ ] `BRU-C3` Enforce account lockout or progressive delays on the service.
- [ ] `BRU-R1` Move the service behind VPN or require key-based or multi-factor authentication.
- [ ] `BRU-E1` Preserve authentication logs and the list of attempted usernames.

<sub>Evidence: RST flags = 2; fwd pkt len max = 23; fwd pkt len max = 22</sub>

## INC-0082 · 🔴 true positive · severity high

**BruteForce** from `172.16.0.1` → `192.168.10.50` · 77 alert(s) · 2017-07-04T17:13:08+00:00 · 3487 s · triaged by `hybrid:llama3.2:3b`

Repeated authentication attempts to guess valid credentials detected on internal web server (192.168.10.50) from source IP 172.16.0.1.

**ATT&CK:** T1110 Brute Force

**Playbook PB-BRUTE, Password guessing against an authentication service:**
- [ ] `BRU-T1` Check authentication logs on the target for failed and successful logins from the source.
- [ ] `BRU-T2` Identify the targeted accounts and whether any login succeeded during or after the burst.
- [ ] `BRU-T3` Check whether the source is an internal tool (monitoring, backup) with a stale password.
- [ ] `BRU-C1` Block the source address at the firewall for the targeted service.
- [ ] `BRU-C2` If a login succeeded, disable the account, revoke its sessions and keys, and reset the password.
- [ ] `BRU-C3` Enforce account lockout or progressive delays on the service.
- [ ] `BRU-R1` Move the service behind VPN or require key-based or multi-factor authentication.
- [ ] `BRU-E1` Preserve authentication logs and the list of attempted usernames.

<sub>Evidence: bwd pkt len max = 976; responder/initiator packet ratio = 1.60; flow iat min = 80</sub>

## INC-0227 · 🔴 true positive · severity high

**PortScan** from `172.16.0.1` → `192.168.10.50` · 29 alert(s) · 2017-07-07T17:52:07+00:00 · 1863 s · triaged by `hybrid:llama3.2:3b`

PortScan detector detected high-severity incident with 29 alerts, involving network service discovery and multiple ports and hosts probed.

**Playbook PB-SCAN, Network scanning and service discovery:**
- [ ] `SCN-T1` Determine whether the scanner is internal (possible compromised host) or external (reconnaissance).
- [ ] `SCN-T2` Check if the source is an authorised vulnerability scanner or asset inventory tool.
- [ ] `SCN-T3` List the ports and hosts probed and which services answered.

<sub>Evidence: urg flag count = 0; payload throughput (B/s) = 0; idle max = 6,007,152</sub>

## INC-0004 · 🟠 needs investigation · severity medium

**Anomaly** from `192.168.10.5` → `172.217.11.10`, `172.217.3.110`, `66.150.102.76` · 32 alert(s) · 2017-07-03T12:15:47+00:00 · 11870 s · triaged by `hybrid:llama3.2:3b`

Medium-severity anomaly detected with 32 alerts, originating from IP 192.168.10.5, targeting external destinations.

**ATT&CK:** T1071 Application Layer Protocol

**Playbook PB-ANOM, Behavioural anomaly lead:**
- [ ] `ANO-T1` Compare the flow with the host's usual activity: same peers, ports and volumes seen before?
- [ ] `ANO-T2` Check whether a known application or scheduled job explains the traffic.
- [ ] `ANO-T3` Look for corroborating signals: other alerts, authentication events, endpoint telemetry.
- [ ] `ANO-C1` No containment for an isolated lead; escalate only if corroborated.
- [ ] `ANO-R1` If benign, record the explanation so that similar leads can be closed faster.
- [ ] `ANO-E1` Keep the flow record and the anomaly score in the case notes.

<sub>Evidence: fwd iat std = 0; bwd rst flags = 0; ACK flags = 0</sub>

## INC-0109 · 🟠 needs investigation · severity medium

**Anomaly** from `172.16.0.1` → `192.168.10.50` · 27 alert(s) · 2017-07-05T13:10:11+00:00 · 3666 s · triaged by `hybrid:llama3.2:3b`

Medium-severity anomaly detected on internal edge firewall, NATed to 172.16.0.1, with unusual traffic to public web server (192.168.10.50) on port 80 via TCP.

**ATT&CK:** T1071 Application Layer Protocol

**Playbook PB-ANOM, Behavioural anomaly lead:**
- [ ] `ANO-T1` Compare the flow with the host's usual activity: same peers, ports and volumes seen before?
- [ ] `ANO-T2` Check whether a known application or scheduled job explains the traffic.
- [ ] `ANO-T3` Look for corroborating signals: other alerts, authentication events, endpoint telemetry.
- [ ] `ANO-C1` No containment for an isolated lead; escalate only if corroborated.
- [ ] `ANO-R1` If benign, record the explanation so that similar leads can be closed faster.
- [ ] `ANO-E1` Keep the flow record and the anomaly score in the case notes.

<sub>Evidence: fwd iat std = 0; active std = 0; fwd urg flags = 0</sub>

