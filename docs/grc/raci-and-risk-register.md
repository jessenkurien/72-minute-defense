# RACI and Risk Register Entry

## RACI — who decides what

| Activity | CISO | IR Lead | SOC (on-call) | Platform Eng. | Business Owner | Legal / DPO | IT Ops |
|---|---|---|---|---|---|---|---|
| Author / revise the Containment Authority Policy | **A** | R | C | C | C | C | C |
| Approve policy and authenticate attestations | **R/A** | C | I | R (VP Eng) | R (VP Ops) | C | I |
| Maintain business context map | I | C | I | R | **A** | I | R |
| Tune precursor weights / intake map | I | **A** | R | C | I | I | I |
| Execute automatic tiers (watch / friction / contain) | I | I | **R/A** (engine) | I | I | I | I |
| Approve Sever tier (two-person) | **R** | **R** | I | I | **R** | C | I |
| Review and recover a contained asset | I | **A** | R | I | C | I | R |
| Run quarterly rehearsal / tabletop | **A** | R | R | C | R | C | C |
| Post-incident review | **A** | R | R | C | C | R | C |
| Regulatory / customer notification decision | **A** | C | I | I | C | **R** | I |
| Approve exception to protections list | **A** | R | I | I | R | C | I |

R = responsible, A = accountable, C = consulted, I = informed. The engine is "responsible" for automatic tiers only inside the ceilings the signers accepted; accountability never leaves the CISO.

## Risk register entry — ransomware (pre-impact containment)

| Field | Value |
|---|---|
| Risk ID | RR-2026-07 |
| Title | Ransomware reaches exfiltration/encryption before containment because decision latency exceeds attacker speed |
| Description | Unit 42's 2026 report gives 72 minutes as the quickest-quartile time to exfiltration. Current end-to-end containment relies on human escalation and a bridge call, measured at [X] minutes in the [date] tabletop. Local exposure depends on measured detection and decision latency. |
| Threat source | Ransomware affiliates using purchased or phished credentials; initial-access brokers |
| Vulnerability | No pre-authorized containment; cross-platform actions require separate consoles and owners; approvers not on call |
| Likelihood (pre-treatment) | High — identity in 89% of intrusions; sector targeted |
| Impact (pre-treatment) | Severe — potential business interruption, recovery cost, regulatory notification, and customer-trust impact; quantify with organization-specific loss data |
| Inherent rating | Critical |
| Treatment | Approved Containment Authority Policy; validated integrations for selected platforms; quarterly rehearsal; trusted two-person approval workflow; external audit anchoring; recovery drills |
| Residual likelihood | Medium — detection coverage gaps at [stages] (see control-mapping coverage table) |
| Residual impact | [Assess after measuring production time-to-contain and recovery time; synthetic template result is 32 min vs the 72-minute benchmark] |
| Residual rating | Medium |
| Risk owner | CISO |
| Control owner | IR Lead |
| Key risk indicators | Worst-case measured time-to-contain; Sever approver response time; coverage-gap stages; policy attestation age; mandatory action-review overdue count; partial-action failure rate |
| Review date | Quarterly, with rehearsal |
| Related | Recovery readiness (RR-2026-08); identity hygiene / long-lived credentials (RR-2026-05) |

## Accepted-impact statements (from the policy, for the record)

The public policy contains illustrative impact statements. A deployment must replace and approve them; do not treat these examples as accepted organizational risk:

- Up to 50 users forced to re-authenticate without notice (Friction).
- Up to 10 accounts disabled and 10 endpoints isolated automatically for up to 12 hours (Contain).
- Removable AWS backup-vault governance locking without per-event approval (Contain), subject to organization-specific validation.
- Cloud-account quarantine and workload-identity disablement only with two named approvers (Sever).
- Executives, break-glass accounts, backup service accounts, domain controllers, and ERP databases never automatically.
