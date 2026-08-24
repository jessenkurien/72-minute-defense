# GDPR: Two Directions

The 72-Minute Defense touches GDPR from two sides. It helps meet obligations during a ransomware incident, and it is itself a processing activity that monitors employees and must comply. A leader is expected to see both. *This is not legal advice; review with counsel or your DPO before relying on it.*

## 1. The program as a GDPR obligation during an incident

| Article | Obligation | How the program helps |
|---|---|---|
| **Art. 32** Security of processing | Ability to restore availability and access in a timely manner; regular testing of effectiveness | Pre-authorized containment; backup vault lock; rehearsals as testing evidence; restore-drill metric |
| **Art. 33** Notification to the supervisory authority | Within 72 hours of becoming aware, unless unlikely to result in risk | Timestamped records may support the incident chronology; they do not by themselves establish legal awareness or whether personal data was affected |
| **Art. 34** Communication to data subjects | Without undue delay when high risk | Same inputs; earlier containment reduces the population affected |
| **Recital 49** | Network and information security is a legitimate interest | Lawful basis for the monitoring that feeds the engine |
| **Art. 28** Processors | Contracts with processors | Determine the role of each vendor for the relevant processing; put required DPAs and transfer mechanisms in place where it acts as a processor |

The 72-minute attacker versus the 72-hour notification clock is a framing a European board remembers.

## 2. The program as a processing activity

The engine observes employee identities and endpoints and takes automated actions against them. That is employee monitoring plus automated decision-making, and it needs its own treatment.

### Lawful basis and purpose
Legitimate interest (Art. 6(1)(f)) in network and information security (Recital 49), limited to the purpose of detecting and containing ransomware precursors. Document the balancing test.

### Data minimization and retention
The audit log stores entity identifiers (UPN, hostname, account id), scores, tier decisions, approver names, and vendor request metadata. It does not store message content, file contents, or credentials. Recommended retention: the incident lifecycle plus the audit cycle (typically 12–24 months), then deletion; rehearsal logs may be retained longer as testing evidence because they contain synthetic identities only.

### Article 22 — automated decisions
Whether Article 22 applies depends on the effect of the action and the surrounding employment context. Do not assume that calling containment a security action resolves the analysis. Document necessity, proportionality, consequences, human review, recovery, appeal/helpdesk paths, and the two-person rule for high-impact actions; obtain counsel or DPO advice.

### Article 35 — DPIA
Automated action against individuals based on behavioral scoring is the kind of processing that warrants a DPIA. Template below.

### Article 30 — record of processing
Add an entry: purpose (ransomware precursor detection and containment), categories of data subjects (employees, contractors, service identities), categories of data (identifiers, security telemetry, decisions), recipients (SOC, IR, vendors as processors), retention, security measures.

### Works councils and national law
In Germany (BetrVG §87(1)(6)) and several other member states, deploying systems capable of monitoring employee behavior requires works-council consultation *before* rollout. Put it in the delivery plan (Stage 1 exit criterion).

### International transfers
If the audit log or vendor telemetry is stored outside the EU/EEA, document the transfer mechanism (adequacy decision, SCCs, DPF as applicable).

## DPIA template (short form)

| Section | Content |
|---|---|
| Description of processing | Ingest security alerts about users/hosts; compute a ransomware precursor score; execute approved containment actions (session revocation, account disable, host isolation, cloud quarantine); log decisions |
| Necessity and proportionality | Use the 72-minute quickest-quartile benchmark with measured local latency [X]; evaluate less intrusive alternatives. Actions are tiered, ceilinged, and subject to mandatory review |
| Risks to individuals | Wrongful lockout (false positive); reputational harm from being "contained"; excessive monitoring; retention creep |
| Measures | Score thresholds and false-positive rehearsal in CI; protections list; helpdesk and recovery runbooks; minimization; retention schedule; access control and external anchoring for audit records; DPO review of policy changes |
| Residual risk | To be assessed by the deploying organization after validating measures and local legal requirements |
| Consultation | DPO, works council (where applicable), employee representatives; supervisory authority only if residual risk high |
| Sign-off | DPO, CISO, HR |

## What to publish, and what not to

Publishing this document is fine and shows maturity. Do not publish your actual audit logs, business context map, or approver names.
