# Control Mapping and Evidence Guide

The 72-Minute Defense **maps to** and **produces evidence for** the frameworks below. It does not make an organization "compliant"; only an assessor can say that. What it does is answer, with an artifact, the question each control asks.

## Evidence the program produces

| Artifact | Produced by | What it evidences |
|---|---|---|
| `policy/containment-authority.yaml` with valid attestations | `72md policy verify` plus protected review evidence | Documented delegation of authority; defined risk tolerances (ceilings, accepted impact); review cadence (`review_by`) |
| `policy/business-context.yaml` | maintained from CMDB | Asset criticality, service ownership, RTO targets |
| `out/*.md`, `out/*.svg`, `out/dashboard.html` | `72md rehearse` | Incident response plan tested; measured time-to-contain; two-person control exercised |
| `audit/*.jsonl` with intact chain | `72md audit verify` plus external anchor | Interior-change-evident chronology of decisions, attempts, and results; completeness depends on external anchoring |
| CI `policy-gate` job history | GitHub Actions | Change-control support: embedded attestations and expected scenarios remain current |
| `docs/tabletop.md` completed record | quarterly exercise | Leadership participation in IR exercises; approver response time measured |

## NIST Cybersecurity Framework 2.0

| Function / Category | How the program maps |
|---|---|
| **GV.RR** Roles, Responsibilities, and Authorities | The policy *is* the documented authority. Tiers name who may act and who must approve. `docs/grc/raci-and-risk-register.md`. |
| **GV.RM** Risk Management Strategy | Ceilings and `accepted_impact` are explicit risk-tolerance statements signed by business owners. |
| **GV.PO** Policy | Versioned, digest-attested, reviewed by `review_by`; protected review authenticates approvers. |
| **ID.AM** Asset Management | Business context map (criticality, service, owner). |
| **DE.AE** Adverse Event Analysis | Precursor chain scoring with ATT&CK mapping; cluster correlation of user + host. |
| **RS.MA** Incident Management | Tiered response executed under pre-authorization; approvals recorded. |
| **RS.AN** Incident Analysis | Audit log records score, stages seen, distance to impact, reasons for every decision. |
| **RS.MI** Incident Mitigation | Containment verbs across identity, endpoint, cloud, backup. |
| **RC.RP** Recovery Plan Execution | Backup governance lock and optional reported restore-drill input; recovery must be tested separately. |
| **PR.AA** Identity Management and Access Control | Session revocation and account disablement as possible first-line actions. |

## NIST SP 800-61 Rev. 3 (Incident Response Recommendations, 2025)

Preparation: policy, business context, rehearsals. Detection and analysis: intake normalizers and scoring. Containment: tiered, pre-authorized actions with mandatory human review. Post-incident: audit records and rehearsal timelines can feed the review.

## ISO/IEC 27001:2022 Annex A

| Control | Mapping |
|---|---|
| A.5.24 Incident management planning and preparation | Policy + rehearsal scenarios |
| A.5.25 Assessment and decision on information security events | Scoring engine; tier thresholds as decision criteria |
| A.5.26 Response to information security incidents | Executor with authority enforcement |
| A.5.27 Learning from incidents | Rehearsal timelines and audit records as inputs to review |
| A.5.28 Collection of evidence | Hash-chained audit log |
| A.5.29 Information security during disruption | Governed containment and decision chronology during an incident |
| A.5.30 ICT readiness for business continuity | Rehearsed containment and separately supplied restore-drill metric |
| A.8.13 Information backup | Backup tampering as a critical precursor; vault lock action |
| A.8.16 Monitoring activities | Intake from SIEM/XDR/cloud |

## SOC 2 (Trust Services Criteria)

CC7.2 (detect anomalies): scoring. CC7.3 (evaluate events): tiers and blast-radius evaluation. **CC7.4 (respond to incidents) and CC7.5 (recover):** rehearsal and audit artifacts may support evidence, but mock execution alone does not demonstrate control design or operating effectiveness in a tenant. CC9.1 (risk mitigation): ceilings and accepted impact.

## CIS Controls v8

Control 11 (Data Recovery): backup tampering detection, vault lock, restore metric. Control 17 (Incident Response Management), especially 17.1 (designate personnel), 17.4 (establish process), 17.7 (conduct routine exercises): policy roles, tiers, and rehearsals.

## PCI DSS 4.0

Requirement 12.10 (incident response plan, tested annually, with roles and authority): policy + rehearsal. 10.x (logging): audit chain.

## Regulatory clocks the audit log supports

| Regime | Clock | How the program helps |
|---|---|---|
| SEC cybersecurity disclosure (Form 8-K Item 1.05) | Verify current rule and applicability with counsel | Timestamped records may support incident chronology; Legal determines materiality and disclosure timing |
| EU NIS2 | 24-hour early warning, 72-hour notification | Same; plus containment timestamps |
| EU DORA (financial entities) | Major-incident reporting | Same |
| GDPR Art. 33 / 34 | 72 hours to supervisory authority; data subjects if high risk | Exfil-staging detection and blast radius indicate whether personal data was reached; see `gdpr.md` |
| CISA / sector regulators | Verify current, sector-specific requirements | Records may support chronology; counsel determines applicability and reporting |

## Detection coverage: turning blind spots into a number

The precursor catalog lists every stage of the chain. Your intake map (`seventytwo/data/intake_map.yaml`) lists which of your rules feed which signal. The difference is your coverage gap. Report it per stage:

| Stage | Signals in catalog | Signals you can produce | Gap |
|---|---|---|---|
| initial_access | 4 | | |
| credential_access | 3 | | |
| discovery | 4 | | |
| defense_evasion | 5 | | |
| exfil_staging | 4 | | |
| impact | 2 | | |

A leader would rather tell the board "we are blind at credential access and here is the plan" than discover it during an incident. Fill this in and put it in the risk register.

## Claims you may make, and claims you may not

You may say: "maps to," "produces evidence for," "supports," "tested quarterly," "measured."
You may not say: "compliant with," "certified," "meets" a framework, unless an assessor has said so for your organization.
