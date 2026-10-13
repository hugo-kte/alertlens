---
id: PB-BRUTE
title: Password guessing against an authentication service
families: [BruteForce]
techniques: [T1110]
---
## Triage
- [BRU-T1] Check authentication logs on the target for failed and successful logins from the source.
- [BRU-T2] Identify the targeted accounts and whether any login succeeded during or after the burst.
- [BRU-T3] Check whether the source is an internal tool (monitoring, backup) with a stale password.
## Containment
- [BRU-C1] Block the source address at the firewall for the targeted service.
- [BRU-C2] If a login succeeded, disable the account, revoke its sessions and keys, and reset the password.
- [BRU-C3] Enforce account lockout or progressive delays on the service.
## Recovery
- [BRU-R1] Move the service behind VPN or require key-based or multi-factor authentication.
## Evidence
- [BRU-E1] Preserve authentication logs and the list of attempted usernames.
