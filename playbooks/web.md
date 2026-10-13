---
id: PB-WEB
title: Attack against a public web application
families: [WebAttack, Heartbleed]
techniques: [T1190]
---
## Triage
- [WEB-T1] Review web server and WAF logs for the requests sent by the source in the incident window.
- [WEB-T2] Check whether any request returned unexpected data, errors or unusually large responses.
- [WEB-T3] Check the patch level of the targeted application and its TLS library.
## Containment
- [WEB-C1] Block the source at the WAF and enable the matching protection rules.
- [WEB-C2] If data exposure is possible, rotate the application's secrets and certificates.
## Recovery
- [WEB-R1] Patch the vulnerable component and re-test.
- [WEB-R2] Review the application for input validation and output encoding issues.
## Evidence
- [WEB-E1] Preserve web, WAF and application logs and a copy of the affected configuration.
