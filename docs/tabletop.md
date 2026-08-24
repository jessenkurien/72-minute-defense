# Tabletop Exercise — "Seventy-Two Minutes"

A 90-minute exercise that produces your organization's first real numbers and tests the two things the technology cannot: whether approvers actually answer, and whether leadership actually accepts the impact they signed.

## Participants

CISO (sponsor), IR Lead (facilitator's counterpart), SOC on-call analyst, IT Ops on-call, platform engineering (identity, endpoint, cloud), a business owner of a crown-jewel service, Legal/DPO, Communications. A facilitator who is not in the response chain. A scribe running `72md` and a stopwatch.

## Preparation

- Policy approved through the organization's protected review process and `72md policy verify` green.
- `72md rehearse` run the day before; keep the dashboard on screen as the "expected" baseline.
- Approvers for the Sever tier confirmed and reachable through the real channel (phone tree, chat, bridge), not the room.
- Two injects printed, not shared in advance.

## Timeline

**T+0 — Inject 1 (fast-72).** Facilitator reads: "Sentinel reports an anomalous sign-in for j.doe from a new country at 02:00. Six minutes later Falcon reports LSASS access on ws-4471." The scribe runs `72md act --events inject1.json --format sentinel` in dry-run and reads the plan aloud: tier, actions, authority, reasons. Ask the SOC analyst: *would you have executed this without the policy?* Record the answer.

**T+15 — Inject 2.** "RMM tool installed on ws-4471. Score now 94; the engine executes the Contain tier automatically and requests Sever approval." Start the stopwatch. The IR Lead must obtain two approvals through the real channel. Stop the stopwatch when the second approval is recorded in that system. CLI `--approve` values may be used to simulate the resulting decision, but they are not authenticated approvals. **The response time is the exercise's primary output.**

**T+35 — Business impact conversation.** The business owner is told which of their service's hosts would be isolated and for how long under the Contain tier. Ask: *do you still accept the impact you signed?* If not, this is the moment to amend the policy, not during an incident.

**T+50 — Inject 3 (crown jewel).** Same attacker pivots to pay-app-03. Walk through why the engine escalates instead of isolating, what the two-person rule costs in minutes, and whether the margin is acceptable. Discuss the alternative: pre-accepting automatic isolation of one payments node with a mandatory two-hour review deadline and an evidence-based recovery decision.

**T+65 — Regulatory clock.** Legal answers: when did we "become aware" for Art. 33? What in the audit log supports that? Would the 8-K materiality analysis start now? Communications drafts the two-sentence holding statement.

**T+80 — Debrief.** Fill in the record below. Decide on policy changes; any changed body requires fresh attestations and protected approval.

## Record

| Measure | Result | Target |
|---|---|---|
| Time to obtain two Sever approvals via real channel | | < 10 min |
| Analyst confidence to execute Contain without a call (1–5) | | ≥ 4 |
| Business owner reaffirmed accepted impact (Y/N) | | Y |
| Approver unreachable events | | 0 |
| Policy changes proposed | | — |
| Rehearsal margin, fast-72 (from `72md rehearse`) | | > 30 min |

## Injects

`inject1.json`, `inject2.json`, `inject3.json` live under `examples/`. Adjust identifiers to your naming conventions before the exercise; the engine will only act on what the business context map recognizes.

## After the exercise

Commit the completed record to `docs/exercises/YYYY-MM.md` (private repo or internal wiki), file the approver-response-time KRI in the risk register, and schedule the next exercise. Two consecutive exercises with approver response under 10 minutes is the evidence that the Sever tier is real.
