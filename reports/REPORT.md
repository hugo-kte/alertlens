# AlertLens evaluation report

_Generated 2026-10-12T18:24:35+00:00 with `llama3.2:3b` (Ollama, CPU)._

**Correlation:** 6,985 alerts → 240 incidents (29× fewer items to look at).

**Rules on every incident:** 100% of attack incidents escalated, 83% of benign incidents closed.

## Stratified sample (60 incidents: every attack incident + 40 random benign ones)

| Triage | Attacks escalated | Attacks missed | Benign closed | Benign escalated | Mean latency |
|---|---:|---:|---:|---:|---:|
| Rules only | 100% | 0 | 80% | 8 | 0.0 s |
| LLM decides | 100% | 0 | 15% | 34 | 37.3 s |
| Hybrid (rules decide, LLM explains) | 100% | 0 | 80% | 8 | 18.8 s |

![Triage comparison](figures/triage_comparison.png)

## Grounding and faithfulness

| Triage | Invalid outputs | Hallucinated step IDs | Hallucinated technique IDs | Summaries with unsupported claims | Steps cited per escalation |
|---|---:|---:|---:|---:|---:|
| LLM decides | 12 | 0 | 0 | 10 / 60 | 5.6 |
| Hybrid (rules decide, LLM explains) | 0 | 32 | 0 | 0 / 60 | 6.6 |

Unsupported claims found in LLM-decides summaries: `technique:T1046`, `technique:T1595`, `technique_name:Active Scanning`, `technique_name:Network Service Discovery`

## Escalations per detector family (LLM decides)

| Family | Incidents | Attack incidents | Escalated |
|---|---:|---:|---:|
| Anomaly | 34 | 1 | 28 |
| Botnet | 6 | 6 | 6 |
| BruteForce | 2 | 2 | 2 |
| DDoS | 1 | 1 | 1 |
| DoS | 3 | 1 | 3 |
| Heartbleed | 1 | 1 | 1 |
| Infiltration | 1 | 0 | 1 |
| PortScan | 11 | 7 | 11 |
| WebAttack | 1 | 1 | 1 |
