"""Executor: runs a Plan through adapters, honoring authority, approvals, and dry-run.

Safety rails (all enforced here, not left to adapters):
  * dry-run unless `armed=True`
  * armed requires a non-template, effective, digest-pinned policy whose attestations verify
  * automatic authority executes; approver authorities require the right number of
    distinct approvals to be passed in (from a ticket, chat approval, or CLI flag)
  * every result is written to the hash-chained audit log
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..adapters.base import Adapter, resolve_adapter
from ..models import CONTAINING, ActionResult, Authority
from ..policy.schema import ContainmentPolicy
from .audit import AuditLog
from .decide import Plan


@dataclass
class Approval:
    role: str
    name: str
    reference: str = ""  # ticket / chat permalink
    verified: bool = False  # set only by a trusted approval integration
    source: str = "operator_input"


@dataclass
class ExecutionReport:
    plan: Plan
    dry_run: bool
    executed: list[ActionResult] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    blocked_reason: str = ""

    @property
    def contained(self) -> bool:
        return (
            bool(self.plan.actions)
            and not self.skipped
            and len(self.executed) == len(self.plan.actions)
            and all(r.ok for r in self.executed)
            and any(r.action.verb in CONTAINING for r in self.executed)
        )


def _approvals_satisfied(
    plan: Plan, approvals: list[Approval], require_verified: bool = False
) -> tuple[bool, str]:
    need = {
        Authority.AUTOMATIC: 0,
        Authority.SINGLE_APPROVER: 1,
        Authority.TWO_PERSON: 2,
        Authority.MANUAL_ONLY: 10**6,
    }[plan.authority]
    if plan.authority == Authority.MANUAL_ONLY:
        return False, "manual_only: engine will not execute; run the actions by hand under IR lead direction"
    if plan.approver_roles:
        invalid = sorted({a.role for a in approvals if a.role not in plan.approver_roles})
        if invalid:
            return (
                False,
                f"approval role(s) not allowed for this plan: {invalid}; allowed: {plan.approver_roles}",
            )
    if require_verified and any(not a.verified for a in approvals):
        return (
            False,
            "live approver-tier execution requires approvals from a trusted integration; CLI approval text is simulation-only",
        )
    if require_verified and any(not a.reference.strip() for a in approvals):
        return False, "live approvals require a non-empty external reference"
    distinct_people = {a.name.strip().casefold() for a in approvals if a.name.strip()}
    if len(distinct_people) < need:
        return (
            False,
            f"{plan.authority.value} requires {need} distinct approver(s) from roles {plan.approver_roles}; have {len(distinct_people)}",
        )
    return True, "ok"


def execute(
    plan: Plan,
    policy: ContainmentPolicy,
    adapters: dict[str, Adapter],
    audit: AuditLog,
    armed: bool = False,
    approvals: list[Approval] | None = None,
    actor: str = "72md",
) -> ExecutionReport:
    approvals = approvals or []
    dry_run = not armed
    rep = ExecutionReport(plan=plan, dry_run=dry_run)

    audit.append(
        "decision",
        actor,
        subject=plan.subject.entity.key(),
        score=plan.subject.score,
        tier=plan.tier.name if plan.tier else None,
        authority=plan.authority.value,
        actions=[f"{a.verb.value}→{a.target.key()}" for a in plan.actions],
        policy_digest=policy.digest(),
        policy_version=policy.version,
        blast_radius={
            "services": plan.blast_radius.services,
            "max_criticality": plan.blast_radius.max_criticality,
            "over_ceiling": plan.blast_radius.over_ceiling,
        },
        reasons=plan.reasons,
    )

    if armed:
        problems = policy.arming_problems(os.environ.get("SEVENTYTWO_POLICY_DIGEST"))
        if problems:
            rep.blocked_reason = "armed run refused: " + "; ".join(problems)
            audit.append("blocked", actor, reason=rep.blocked_reason)
            return rep
    if not plan.actions:
        rep.blocked_reason = "no actions in plan"
        return rep
    ok, why = _approvals_satisfied(plan, approvals, require_verified=armed)
    if not ok:
        audit.append(
            "awaiting_approval" if plan.authority != Authority.MANUAL_ONLY else "manual_only",
            actor,
            subject=plan.subject.entity.key(),
            reason=why,
        )
        if plan.fallback is not None and plan.fallback.actions:
            fb = execute(plan.fallback, policy, adapters, audit, armed=armed, approvals=[], actor=actor)
            rep.executed.extend(fb.executed)
            rep.skipped.extend(fb.skipped)
            rep.blocked_reason = (
                f"tier '{plan.tier.name}' awaiting approval ({why}); "
                f"executed pre-authorized tier '{plan.fallback.tier.name}' meanwhile"
            )
        else:
            rep.blocked_reason = why
        return rep

    for action in plan.actions:
        adapter = resolve_adapter(action.target, adapters)
        if adapter is None:
            rep.skipped.append(
                f"{action.verb.value}→{action.target.key()}: no adapter for platform '{action.target.platform or '?'}'"
            )
            audit.append(
                "skipped", actor, action=action.verb.value, target=action.target.key(), reason="no adapter"
            )
            continue
        if not adapter.supports(action.verb):
            rep.skipped.append(
                f"{action.verb.value}→{action.target.key()}: adapter '{adapter.name}' does not support the verb"
            )
            audit.append(
                "skipped",
                actor,
                action=action.verb.value,
                target=action.target.key(),
                reason=f"adapter {adapter.name} does not support verb",
            )
            continue
        audit.append(
            "action_attempt",
            actor,
            action=action.verb.value,
            target=action.target.key(),
            adapter=adapter.name,
            dry_run=dry_run,
            policy_digest=policy.digest(),
            policy_version=policy.version,
            review_after_minutes=action.review_after_minutes,
        )
        try:
            result = adapter.execute(action, dry_run=dry_run)
        except Exception as exc:  # noqa: BLE001 - final boundary: adapters must not crash the run
            result = ActionResult(
                action=action,
                adapter=adapter.name,
                dry_run=dry_run,
                ok=False,
                detail=f"adapter raised {type(exc).__name__}: {exc}",
            )
        rep.executed.append(result)
        audit.append(
            "action",
            actor,
            action=action.verb.value,
            target=action.target.key(),
            adapter=result.adapter,
            dry_run=dry_run,
            ok=result.ok,
            detail=result.detail,
            request=result.request,
            approvals=[
                {
                    "role": a.role,
                    "name": a.name,
                    "ref": a.reference,
                    "verified": a.verified,
                    "source": a.source,
                }
                for a in approvals
            ],
            policy_digest=policy.digest(),
            policy_version=policy.version,
            review_after_minutes=action.review_after_minutes,
        )
    return rep
