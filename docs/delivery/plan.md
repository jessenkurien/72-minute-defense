# Delivery Plan (PRINCE2-aligned)

The 72-Minute Defense is delivered as a staged project with a business case, a project board, tolerances, and stage gates. Manage-by-exception applies twice: to the project (the board sets tolerances, the project manager acts within them) and to the product (the business sets ceilings, the SOC acts within them). Keep the ceremony proportionate; the point is judgment, not paperwork.

## Business case (summary)

**Problem.** Decision latency exceeds attacker speed. Measured containment in the last tabletop: [X] minutes; attacker exfiltration benchmark: 72 minutes.
**Options.** (a) Do nothing; (b) enable vendor automatic containment without governance (frequently switched off after the first business complaint); (c) governed, cross-platform pre-authorization with measurement (this project).
**Benefits.** Time-to-contain under 45 minutes worst case; evidence for SOC 2 / ISO / insurer; reduced incident cost; defensible authority.
**Costs.** ~[N] engineering days for adapters and intake; leadership time for authenticated policy approval (2 hours); quarterly 90-minute exercises.
**Risks.** Over-blocking; approver unavailability; detection coverage gaps; works-council timeline in EU sites.
**Timescale.** 90 days to full operation.

## Project board

Executive: CISO. Senior User: IR Lead (represents the SOC and the business owners). Senior Supplier: Head of Platform Engineering. Project Assurance: Internal Audit or GRC lead. Project Manager: [name].

## Tolerances (project level)

Time: ±2 weeks per stage. Cost: ±15%. Scope: adapters may be deferred but the policy, rehearsal, and audit log may not. Quality: every stage exit requires `72md rehearse --fail-if-late` green, attestations current, and protected review evidence. Risk: any single rehearsal scenario failing after a change is an exception to the board.

## Stages

### Stage 0 — Initiation (weeks 0–2)
Products: business case; business context map v1 from the CMDB; intake map for the current SIEM/XDR rules; draft policy with placeholder ceilings; DPIA draft; works-council notification where required.
Exit: project board approves; DPO has reviewed the DPIA draft.

### Stage 1 — Policy and dry-run (weeks 2–5)
Products: approved operational policy v1 (all required roles authenticated outside the YAML); engine deployed in dry-run receiving live alerts; first rehearsal numbers; tabletop #1 with approver response time measured.
Exit: dry-run plans reviewed for two weeks with zero "would have been wrong" verdicts from the IR Lead; false-positive scenario passes; approver response time under 15 minutes.

### Stage 2 — Live, friction and contain (weeks 5–9)
Products: narrowly scoped live pilot for Friction and selected Contain actions on non-production or approved standard-criticality assets; mandatory-review alerts active; helpdesk and recovery runbooks live; external audit anchoring active.
Exit: every pilot action reviewed; no unplanned business impact; failure and recovery paths exercised; KRIs reported to the risk committee.

### Stage 3 — Full operation (weeks 9–13)
Products: Sever tier considered only after a trusted approval integration is validated; remaining adapters validated in sandbox; dashboard on the security metrics pack; quarterly rehearsal scheduled; policy v2 with tuned weights and renewed attestations.
Exit: worst-case rehearsed time-to-contain under 45 minutes; approver response under 10 minutes in tabletop #2; project closed to operations with the IR Lead as service owner.

## Registers

- Risk register: see `docs/grc/raci-and-risk-register.md` (project risks: adapter API changes, vendor rate limits, approver availability, works-council timing).
- Issue log and lessons log: kept in the project tracker; lessons feed the policy `notes` field and the next rehearsal scenarios.
- Quality register: CI runs are the quality records.

## Highlight report (one paragraph, fortnightly, to the board)

Stage, RAG status, tolerance position, rehearsal numbers this fortnight, KRIs, exceptions raised, decisions needed.

## Note on PMP-oriented audiences

The same plan reads as initiation → planning → executing (three increments) → monitoring (rehearsals, KRIs) → closing. Use whichever vocabulary the audience knows; the stage gates and tolerances are what matter.
