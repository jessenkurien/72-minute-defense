# Architecture

```
  SIEM / XDR / cloud alerts                       policy/containment-authority.yaml (attested)
  (Sentinel, Splunk, Falcon, GuardDuty, generic)  policy/business-context.yaml
            │                                              │
            ▼                                              ▼
  ┌───────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
  │ intake/           │───▶│ scoring/         │───▶│ engine/decide       │
  │ normalize to      │    │ chain score,     │    │ tier, authority,    │
  │ PrecursorEvent    │    │ cluster, decay,  │    │ protections,        │
  │ (unmapped → drop) │    │ critical floor   │    │ ceilings, fallback  │
  └───────────────────┘    └──────────────────┘    └──────────┬──────────┘
                                                              │ Plan
                                                              ▼
                       ┌──────────────────────────────────────────────────────┐
                       │ engine/execute   dry-run default · armed needs valid │
                       │ digest pin · approvals per authority · fallback tier │
                       └───────┬───────────────────────────────┬──────────────┘
                               │                               │
                               ▼                               ▼
         ┌──────────────────────────────┐        ┌──────────────────────────┐
         │ adapters/  entra · defender  │        │ engine/audit             │
         │ okta · crowdstrike · aws ·   │        │ hash-chained JSONL       │
         │ mock   (official APIs only)  │        │ decisions/approvals/acts │
         └──────────────────────────────┘        └──────────────────────────┘

  rehearsal/  scenarios/*.yaml ──▶ same scoring + decide + execute (mock) ──▶ timeline, metrics
  report/     SVG timeline · Markdown · dashboard.html (board view)
```

## Design decisions

**Policy is validated data with digest-bound attestations.** The engine reads YAML validated by a Pydantic schema. Authority is a property of the policy, not the code. The embedded digest detects body changes; a protected review system must authenticate approvers, and live use independently pins the expected digest.

**Score, don't checklist.** Weighted, decaying, stage-bonused scoring over clustered entities. One weak signal cannot act; one critical signal always can. See `seventytwo/data/precursors.yaml`.

**Do what is pre-authorized now; escalate the rest.** `decide()` attaches a `fallback` plan (the highest automatic tier the score earned) to any plan that needs approval. `execute()` runs the fallback while the higher tier waits. This single rule is what wins the fast-72 rehearsal.

**Vendor-neutral verbs, vendor-specific adapters.** The policy never names a vendor. Adapters use documented REST APIs or boto3 and are dry-run by default. They return a request preview; live calls that require discovery can produce a longer request sequence.

**Evidence by construction, with a defined boundary.** Decisions, action attempts, and results are appended to a hash-chained log. Rehearsals use the same artifact type. The chain detects interior modification but needs immutable external anchoring to support completeness claims.

**Rehearsal is the test suite for the policy.** Scenarios declare what a correct policy should do (`expect: contain | no_action`). CI runs them on every change; a weakened policy fails the build.

## Data flow for one alert

1. Vendor payload → `intake.normalize(fmt, payload)` → `PrecursorEvent` (or dropped as unmapped, reported).
2. `scoring.score_events(events)` → `EntityScore` per cluster: score, critical flag, stages, distance to impact.
3. `engine.decide(score, policy, ctx)` → `Plan`: tier, authority, actions, blast radius, reasons, fallback.
4. `engine.execute(plan, policy, adapters, audit, armed, approvals)` → `ExecutionReport`; audit records written.
5. Adapter `execute(action, dry_run)` → `ActionResult` with request metadata. Recovery uses the adapter's `revert()` under IR direction; no automatic sweep is implemented.

## Extending

New precursor: add to `seventytwo/data/precursors.yaml` and map your rule names in `intake_map.yaml`.
New adapter: subclass `Adapter`, declare `supported` verbs, implement `execute`/`revert` with a dry-run branch, register in `adapters/__init__.py`, add tests with `httpx.MockTransport`.
New scenario: a YAML in `scenarios/` with events, detect delays, approvals with response times, and `expect`.
