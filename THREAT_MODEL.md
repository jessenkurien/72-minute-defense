# Threat model — The 72-Minute Defense

A service that can disable identities, isolate hosts, or quarantine cloud accounts can become a denial-of-service mechanism if compromised or misconfigured. This is a reference threat model, not a substitute for a deployment-specific assessment.

## Protected assets

- Containment policy and the independent copy of its expected digest
- Adapter identities, secrets, API tokens, and cloud roles
- Business context and criticality map
- Approval records and integration signing keys
- Decision/action audit records
- Availability of identities, endpoints, cloud accounts, and backups

## Trust boundaries

Alerts, policy changes, business-context updates, CLI input, approval integrations, vendor APIs, the execution host, CI, and audit storage cross separate trust boundaries. A production design should diagram its actual identities and network paths.

## Threats and controls

**T1. Weaponized containment.** An attacker injects alerts or controls the engine and tries to lock out the organization. The included template cannot be armed. Operational arming requires an effective, unexpired, attested policy and an out-of-band digest pin. Automatic actions remain bounded by unique-entity ceilings, protected-entity rules, and fail-safe escalation for assets missing from the business context. Keep break-glass identities outside all adapter scopes.

**T2. Policy tampering or forged attestations.** A body edit makes existing SHA-256 attestations stale, but an embedded digest is not a digital signature and does not authenticate the names in the YAML. Production assurance must come from protected branches, required reviewers, signed commits or tags, and/or a trusted external approval system. The independently pinned digest prevents the policy and its embedded attestations from being silently replaced together on the execution host.

**T3. Approval spoofing.** Two-person approval requires two distinct allowed identities. CLI strings are simulation-only and cannot authorize an armed approver-tier action. A production approval connector must authenticate the identity, role, decision, policy digest, plan digest, target scope, expiry, and incident reference; it must prevent replay. That connector is not included in version 0.1.0.

**T4. Scoring manipulation.** Exact delivery retries are deduplicated, conflicting reuse of a source event ID is rejected, and repeated occurrences of one signal contribute only their strongest decayed value. Critical-tier floors require confidence of at least 0.8. Attackers may still evade source detections or poison trusted telemetry. Tune against local data and retain human escalation for ambiguous cases.

**T5. Incomplete or stale business context.** An unknown target never inherits standard criticality; it escalates to two-person review. This protects safety but may slow response. Production deployments should continuously reconcile the context map with the CMDB and cloud inventory and alert on coverage gaps.

**T6. Adapter misuse and API drift.** Adapters use narrow vendor-neutral verbs and validate entity types. Dry-run is the default. All current adapters are mock/stub tested, not tenant validated. API behavior, permissions, rate limits, and rollback semantics must be proven in a non-production tenant before live use.

**T7. Unsafe recovery.** `mandatory_review_minutes` is a review deadline, not an automatic rollback timer. Automatically re-enabling an identity or reconnecting a host could restore attacker access. Recovery requires evidence-based IR direction. AWS Backup Vault Lock is requested in removable governance mode; the project deliberately avoids immutable compliance mode.

**T8. Credential compromise.** Credentials come from environment variables or the cloud credential chain and are excluded from policy and audit files. Use a dedicated hardened workload identity with only the exact permissions required, short-lived credentials where supported, outbound allowlists, and separate identities per adapter. Never run an armed engine from an analyst workstation.

**T9. Audit deletion or replacement.** Hash chaining detects interior edit, reordering, and deletion. It does not detect clean tail truncation or replacement of the entire log with a newly generated chain. Export records continuously to independently administered immutable storage and pin or sign checkpoints externally.

**T10. Dependency or CI compromise.** CI uses read-only permissions, avoids credential persistence, and pins third-party GitHub Actions to immutable commit references. Production builds should also pin and hash Python dependencies, produce an SBOM and provenance, scan releases, and deploy only verified artifacts. Version 0.1.0 does not implement that full release pipeline.

**T11. Privacy and employment-law harm.** The system processes employee identifiers and security telemetry and may take disruptive actions. Complete a DPIA or equivalent assessment, data-minimization and retention decisions, legal/DPO review, works-council consultation where required, and clear helpdesk/appeal procedures before deployment.

## Residual risks

- A trusted alert source can still be wrong or compromised.
- Two correctly authenticated approvers can make a bad decision.
- Vendor control-plane compromise is outside this project's boundary.
- A governance-mode backup lock is removable by an authorized administrator and is not protection from a fully privileged attacker.
- Cross-platform actions are not atomic; partial containment is possible and is reported as such.
- Regulatory and control mappings do not establish compliance or operating effectiveness.

## Required validation before any live pilot

1. Create a non-template policy with organization-specific accepted impacts and protections.
2. Authenticate approvals outside the YAML and pin the approved digest independently.
3. Validate every enabled adapter in a non-production tenant, including failure and recovery.
4. Measure actual ingestion, scoring, approval, API, and recovery latency.
5. Anchor audit checkpoints in external immutable storage.
6. Exercise false positives, partial failures, compromised approvers, stale inventory, and vendor outages.
7. Obtain security, platform, business-owner, privacy/legal, and change-management approval.
