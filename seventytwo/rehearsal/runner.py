"""Rehearsal: replay a synthetic intrusion through the real policy and record the clock.

The output is the number that matters: minutes from first malicious activity to containment,
against the attacker's 72-minute exfiltration clock. Run it before you arm the policy, run it
after every policy change, and run it on a schedule — each run is audit evidence that the
plan was exercised and may support control evidence (for example, SOC 2 CC7.4/CC7.5,
ISO/IEC 27001:2022 A.5.30, and NIST CSF RS/RC), subject to assessor evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from .. import ATTACKER_CLOCK_MINUTES, PROJECT_CREATOR, PROJECT_NAME, PROJECT_URL
from ..adapters.mock import MockAdapter
from ..engine.audit import AuditLog
from ..engine.context import BusinessContext
from ..engine.decide import Plan, decide
from ..engine.execute import Approval, execute
from ..models import CONTAINING, Authority, Entity, PrecursorEvent
from ..policy.schema import ContainmentPolicy
from ..scoring.engine import Catalog, score_events


@dataclass
class Scenario:
    name: str
    description: str
    attacker_exfil_minute: float
    attacker_milestones: list[dict]  # [{minute, label}]
    events: list[dict]  # [{minute, signal, entity:{type,id,platform}, related:[...], detect_delay: min}]
    approvals: list[dict] = field(
        default_factory=list
    )  # approvals available during rehearsal, with response minutes
    expect: str = "contain"  # "contain" | "no_action"  — what a correct policy should do


@dataclass
class TimelineEntry:
    minute: float
    kind: str  # attacker | detect | score | decision | action | contain | approval
    text: str
    score: float | None = None
    tier: str | None = None


@dataclass
class RehearsalResult:
    scenario: str
    timeline: list[TimelineEntry]
    first_precursor_minute: float | None
    detect_minute: float | None
    decision_minute: float | None
    contain_minute: float | None
    attacker_exfil_minute: float
    final_plan: Plan | None
    actions_taken: list[str]
    authority_used: str | None
    approvals_used: list[str]
    expect: str = "contain"
    friction_minute: float | None = None

    @property
    def passed(self) -> bool:
        """Did the policy do what this scenario says a correct policy should do?"""
        if self.expect == "no_action":
            return self.contain_minute is None and not self.actions_taken
        return self.contained_before_exfil

    @property
    def margin_minutes(self) -> float | None:
        return (
            None
            if self.contain_minute is None
            else round(self.attacker_exfil_minute - self.contain_minute, 1)
        )

    @property
    def contained_before_exfil(self) -> bool:
        return self.contain_minute is not None and self.contain_minute < self.attacker_exfil_minute

    def metrics(self) -> dict:
        return {
            "project": {
                "name": PROJECT_NAME,
                "creator": PROJECT_CREATOR,
                "url": PROJECT_URL,
            },
            "scenario": self.scenario,
            "attacker_clock_minutes": self.attacker_exfil_minute,
            "first_precursor_minute": self.first_precursor_minute,
            "time_to_detect_minutes": self.detect_minute,
            "time_to_decide_minutes": self.decision_minute,
            "time_to_contain_minutes": self.contain_minute,
            "margin_minutes": self.margin_minutes,
            "contained_before_exfiltration": self.contained_before_exfil,
            "friction_minute": self.friction_minute,
            "expected": self.expect,
            "passed": self.passed,
            "authority_used": self.authority_used,
            "actions": self.actions_taken,
        }


def load_scenario(path: Path) -> Scenario:
    with open(path, encoding="utf-8") as f:
        d = yaml.safe_load(f)
    return Scenario(
        name=d["name"],
        description=d.get("description", ""),
        attacker_exfil_minute=float(d.get("attacker_exfil_minute", ATTACKER_CLOCK_MINUTES)),
        attacker_milestones=d.get("attacker_milestones", []),
        events=d["events"],
        approvals=d.get("approvals", []),
        expect=d.get("expect", "contain"),
    )


def rehearse(
    scenario: Scenario,
    policy: ContainmentPolicy,
    catalog: Catalog,
    ctx: BusinessContext,
    audit: AuditLog,
    adapter: MockAdapter | None = None,
    t0: datetime | None = None,
    engine_latency_minutes: float = 0.5,
) -> RehearsalResult:
    """Replays events in time order. Each event becomes visible at minute + detect_delay
    (pipeline latency). After each visible event the engine re-scores and re-decides. The
    first automatic tier-with-actions plan executes; approver tiers wait for the scenario's
    approvals (each with a response time), which is how a rehearsal shows the cost of a
    two-person rule honestly."""
    t0 = t0 or datetime(2026, 1, 1, tzinfo=timezone.utc)
    adapter = adapter or MockAdapter()
    adapters = {"mock": adapter}
    tl: list[TimelineEntry] = []
    for m in scenario.attacker_milestones:
        tl.append(TimelineEntry(float(m["minute"]), "attacker", m["label"]))
    tl.append(TimelineEntry(scenario.attacker_exfil_minute, "attacker", "EXFILTRATION (attacker clock)"))

    visible: list[tuple[float, PrecursorEvent]] = []
    for i, e in enumerate(scenario.events):
        vis = float(e["minute"]) + float(e.get("detect_delay", 2))
        ent = Entity.model_validate(e["entity"])
        rel = [Entity.model_validate(r) for r in e.get("related", [])]
        ev = PrecursorEvent(
            id=f"{scenario.name}-{i}",
            ts=t0 + timedelta(minutes=float(e["minute"])),
            signal=e["signal"],
            entity=ent,
            related=rel,
            source=e.get("source", "rehearsal"),
            confidence=float(e.get("confidence", 1.0)),
        )
        visible.append((vis, ev))
    visible.sort(key=lambda p: p[0])

    first = min(float(e["minute"]) for e in scenario.events) if scenario.events else None
    detect = decision = contain = None
    final_plan = None
    actions_taken: list[str] = []
    authority_used = None
    approvals_used: list[str] = []
    seen: list[PrecursorEvent] = []
    pending_since: float | None = None
    done: set[str] = set()
    friction = None

    for idx, (vis_minute, ev) in enumerate(visible):
        if contain is not None:
            break
        next_vis = visible[idx + 1][0] if idx + 1 < len(visible) else float("inf")
        seen.append(ev)
        now = t0 + timedelta(minutes=vis_minute)
        tl.append(TimelineEntry(vis_minute, "detect", f"{ev.signal} on {ev.entity.key()} (from {ev.source})"))
        scores = score_events(seen, catalog, now=now)
        if not scores:
            continue
        top = scores[0]
        tl.append(
            TimelineEntry(
                vis_minute,
                "score",
                f"score {top.score} · stages {[s.value for s in top.stages_seen]} · {top.distance_to_impact} to impact",
                score=top.score,
            )
        )
        plan = decide(top, policy, ctx)
        final_plan = plan
        if plan.tier is None:
            continue
        if detect is None:
            detect = vis_minute
        d_minute = round(vis_minute + engine_latency_minutes, 1)
        tl.append(
            TimelineEntry(
                d_minute,
                "decision",
                f"tier {plan.tier.name} · {plan.authority.value} · {len(plan.actions)} action(s)",
                tier=plan.tier.name,
            )
        )
        plan.actions = [a for a in plan.actions if f"{a.verb.value}→{a.target.key()}" not in done]
        if plan.fallback is not None:
            plan.fallback.actions = [
                a for a in plan.fallback.actions if f"{a.verb.value}→{a.target.key()}" not in done
            ]
        if not plan.actions and not (plan.fallback and plan.fallback.actions):
            continue
        approvals: list[Approval] = []
        exec_minute = d_minute
        if plan.authority != Authority.AUTOMATIC:
            if pending_since is None:
                pending_since = d_minute
                tl.append(
                    TimelineEntry(
                        d_minute, "approval", f"waiting for {plan.authority.value}: {plan.approver_roles}"
                    )
                )
            # scenario approvals arrive `response_minutes` after the request
            for ap in scenario.approvals:
                arrive = pending_since + float(ap.get("response_minutes", 15))
                if ap.get("role") in plan.approver_roles or not plan.approver_roles:
                    approvals.append(
                        Approval(role=ap["role"], name=ap.get("name", "rehearsal"), reference="rehearsal")
                    )
                    exec_minute = max(exec_minute, arrive)
            need = {Authority.SINGLE_APPROVER: 1, Authority.TWO_PERSON: 2}.get(plan.authority, 0)
            if len(approvals) < need:
                tl.append(
                    TimelineEntry(
                        d_minute,
                        "approval",
                        f"only {len(approvals)}/{need} approvals available; tier '{plan.tier.name}' blocked"
                        + (
                            f" — executing pre-authorized tier '{plan.fallback.tier.name}' now"
                            if plan.fallback and plan.fallback.actions
                            else ""
                        ),
                    )
                )
                approvals = []
                exec_minute = d_minute
            elif exec_minute > next_vis:
                # Approvals land after the next alert; that alert will produce a bigger plan which
                # inherits the same pending request. Run only the pre-authorized fallback for now.
                tl.append(
                    TimelineEntry(
                        d_minute,
                        "approval",
                        f"approvals expected at minute {exec_minute:g}; tier '{plan.tier.name}' pending"
                        + (
                            f" — executing pre-authorized tier '{plan.fallback.tier.name}' now"
                            if plan.fallback and plan.fallback.actions
                            else ""
                        ),
                    )
                )
                approvals = []
                exec_minute = d_minute
                if not (plan.fallback and plan.fallback.actions):
                    continue
            else:
                for ap in approvals[:need]:
                    tl.append(TimelineEntry(exec_minute, "approval", f"approved by {ap.role} ({ap.name})"))
                    approvals_used.append(ap.role)
        rep = execute(plan, policy, adapters, audit, armed=False, approvals=approvals, actor="72md rehearsal")
        if rep.blocked_reason and not rep.executed:
            tl.append(TimelineEntry(exec_minute, "decision", f"blocked: {rep.blocked_reason}"))
            continue
        contained_now = False
        for r in rep.executed:
            key = f"{r.action.verb.value}→{r.action.target.key()}"
            done.add(key)
            tl.append(
                TimelineEntry(
                    exec_minute,
                    "action",
                    f"{r.action.verb.value} → {r.action.target.key()} ({'ok' if r.ok else 'FAILED'})",
                )
            )
            actions_taken.append(key)
            if r.ok and r.action.verb in CONTAINING:
                contained_now = True
        if rep.executed and not contained_now and friction is None:
            friction = round(exec_minute + engine_latency_minutes, 1)
            tl.append(
                TimelineEntry(
                    friction,
                    "friction",
                    "friction applied (sessions revoked / MFA reset) — attacker slowed, not stopped",
                )
            )
        if contained_now:
            decision = d_minute
            contain = round(exec_minute + engine_latency_minutes, 1)
            authority_used = (
                plan.authority.value
                if not (rep.blocked_reason and plan.fallback)
                else plan.fallback.authority.value
            )
            tl.append(
                TimelineEntry(
                    contain,
                    "contain",
                    f"CONTAINED at minute {contain} · margin {round(scenario.attacker_exfil_minute - contain, 1)} min",
                )
            )

    tl.sort(
        key=lambda t: (
            t.minute,
            ["attacker", "detect", "score", "decision", "approval", "action", "friction", "contain"].index(
                t.kind
            ),
        )
    )
    return RehearsalResult(
        scenario.name,
        tl,
        first,
        detect,
        decision,
        contain,
        scenario.attacker_exfil_minute,
        final_plan,
        actions_taken,
        authority_used,
        approvals_used,
        scenario.expect,
        friction,
    )
