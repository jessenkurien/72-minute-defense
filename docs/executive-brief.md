# Executive Brief — The 72-Minute Defense

*One page. For the board, the audit committee, and the executive team.*

## The situation

In Palo Alto Networks Unit 42's 2026 incident-response data, the quickest quartile reached data exfiltration in 72 minutes, and identity weaknesses appeared in 89% of investigations. That is a benchmark, not a prediction for every incident.

Our detection tools generally see the warning signs. Our incident response process was designed for a multi-week attacker: detect, escalate, convene, decide, contain. Measured end to end, that process takes hours. We lose not because we cannot see the attack, and not because we lack the tools to stop it, but because the *decision* to stop it takes longer than the attack.

## The decision we are asking leadership to make now, not at 2 a.m.

We propose an authenticated, reviewed **Containment Authority Policy** that pre-authorizes specific containment actions at specific evidence levels, inside boundaries the business accepts in advance:

| Tier | When | The SOC may, without a call | Accepted impact |
|---|---|---|---|
| Watch | early, weak signals | page the analyst | none |
| Friction | credible chain forming | revoke sessions (≤ 50 users) | brief login disruption; helpdesk runbook ready |
| Contain | attacker is a step or two from impact, or one critical signal (backup tampering, EDR tampering, bulk egress) | disable the account, isolate the endpoint (≤ 10 each), lock the backup vault; auto-reviewed within 12 h | a user or workstation offline for up to 12 h |
| Sever | wide or crown-jewel impact | quarantine a cloud account, disable workload identities | **two named approvers**; may take a business service offline |

Executives, domain controllers, crown-jewel systems, and unknown assets are never touched automatically; they escalate. Actions carry mandatory review deadlines, not blind auto-revert. The backup action uses removable AWS governance mode. Decision attempts and results are written to a hash-chained audit log that requires external anchoring for completeness assurance.

## What we get

A single measured number, rehearsed before any pilot and re-measured after every policy change: **time from first warning sign to containment, against a 72-minute benchmark.** The included synthetic scenarios contain at minute 19 automatically and minute 28 when two approvers respond after 8 and 14 minutes. These are reference outputs; the organization must replace scenario latency with measured production data.

The program can support evidence collection for incident-response testing, decision chronology, and delegation of authority. Control owners, Legal, and assessors determine whether that evidence is sufficient for SOC 2, ISO/IEC 27001, NIST CSF 2.0, or a notification analysis.

## What we are asking for

1. Sign-off on the policy tiers and accepted impacts from the CISO, VP Engineering, and VP Operations (30-minute review; the document is four pages).
2. Named approvers for the Sever tier with a 10-minute response commitment during incidents, rehearsed quarterly.
3. A 90-day, three-stage rollout: dry-run only, then live on friction-level actions, then full. Each stage ends with a go/no-go on the rehearsal numbers.

## What could go wrong, and the answer

*Over-blocking.* A false positive locks out a VP. Answer: tiers, unique-entity ceilings, protections, unknown-asset escalation, mandatory review, and a helpdesk/recovery runbook.
*Attackers game the scoring.* Answer: critical signals cannot be suppressed by "looking quiet"; the policy floor triggers on any one of them.
*Detection gaps.* Answer: the program reports which stages of the chain we cannot see, so blindness is a known number with a plan, not a surprise during an incident.

*Prepared by:* Jessen Kurien · *Date:* [date] · *Policy version:* 3 public template
