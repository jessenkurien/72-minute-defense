"""Decision engine: (scores, policy, business context) -> containment Plan.

The engine never invents authority. Every action in a plan traces to a tier the policy
defines, and every deviation (escalation, ceiling breach, protected principal) is recorded
as a reason a human can read later.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from ..models import REVERSIBLE, VERB_TARGETS, Action, Authority, Entity, EntityType, Verb
from ..policy.schema import ContainmentPolicy, Tier
from ..scoring.engine import EntityScore
from .context import BusinessContext, crit_at_least


@dataclass
class BlastRadius:
    entities: list[Entity]
    services: list[str]
    max_criticality: str
    owners: list[str]
    over_ceiling: list[str] = field(default_factory=list)


@dataclass
class Plan:
    subject: EntityScore
    tier: Tier | None
    authority: Authority
    actions: list[Action]
    blast_radius: BlastRadius
    reasons: list[str]
    approver_roles: list[str] = field(default_factory=list)
    fallback: Plan | None = None  # pre-authorized actions to run NOW while this plan awaits approval

    @property
    def automatic(self) -> bool:
        return self.authority == Authority.AUTOMATIC and bool(self.actions)


def _protected(entity: Entity, policy: ContainmentPolicy, ctx: BusinessContext) -> str | None:
    pats = policy.protections.principals if entity.type != EntityType.HOST else policy.protections.hosts
    for p in pats:
        if fnmatch.fnmatch(entity.id.lower(), p.lower()):
            return f"{entity.key()} matches protected pattern '{p}'"
    floor = policy.protections.criticality_at_least
    if floor and crit_at_least(ctx.criticality(entity), floor):
        return f"{entity.key()} criticality '{ctx.criticality(entity)}' >= protected floor '{floor}'"
    return None


def _escalate(a: Authority, b: Authority) -> Authority:
    order = [Authority.AUTOMATIC, Authority.SINGLE_APPROVER, Authority.TWO_PERSON, Authority.MANUAL_ONLY]
    return max(a, b, key=order.index)


def decide(subject: EntityScore, policy: ContainmentPolicy, ctx: BusinessContext) -> Plan:
    plan = _decide_tier(subject, policy, ctx, policy.tier_for_score(subject.score, subject.critical))
    if subject.critical and policy.critical_signals_force_tier:
        plan.reasons.insert(0, f"critical signal present → tier floor '{policy.critical_signals_force_tier}'")
    # Do what is pre-authorized now; escalate the rest. A higher tier waiting on approvers must
    # never block the automatic tier the score already earned.
    if plan.tier is not None and plan.authority != Authority.AUTOMATIC:
        lower = policy.highest_automatic_below(plan.tier, subject.score)
        if lower is not None:
            fb = _decide_tier(subject, policy, ctx, lower)
            if fb.authority == Authority.AUTOMATIC and fb.actions:
                plan.fallback = fb
                plan.reasons.append(
                    f"while awaiting {plan.authority.value}: execute pre-authorized tier '{lower.name}' immediately "
                    f"({', '.join(a.verb.value for a in fb.actions)})"
                )
    return plan


def _decide_tier(
    subject: EntityScore, policy: ContainmentPolicy, ctx: BusinessContext, tier: Tier | None
) -> Plan:
    reasons: list[str] = []
    if tier is None:
        reasons.append(f"score {subject.score} below lowest tier threshold; monitor only")
        return Plan(subject, None, Authority.MANUAL_ONLY, [], _radius([], ctx), reasons)

    reasons.append(
        f"score {subject.score} (stages: {', '.join(s.value for s in subject.stages_seen)}; "
        f"{subject.distance_to_impact} stage(s) to impact) → tier '{tier.name}' ({tier.authority.value})"
    )
    authority = tier.authority
    approvers = list(tier.approver_roles)

    # build candidate actions: each tier verb applied to every cluster entity of a matching type
    actions: list[Action] = []
    for verb in tier.actions:
        for ent in subject.cluster:
            if ent.type in VERB_TARGETS[verb] and verb != Verb.NOTIFY:
                actions.append(
                    Action(
                        verb=verb,
                        target=ent,
                        tier=tier.name,
                        reversible=REVERSIBLE[verb],
                        review_after_minutes=tier.mandatory_review_minutes,
                        reason=f"tier {tier.name}: {subject.contributing[0][0] if subject.contributing else 'score'}",
                    )
                )
    # Unknown assets fail safe. A missing CMDB/context entry must never silently inherit
    # "standard" criticality and become eligible for automatic containment.
    unique_targets = {a.target.key(): a.target for a in actions}
    for target in unique_targets.values():
        if not ctx.recognizes(target):
            authority = _escalate(authority, Authority.TWO_PERSON)
            approvers = approvers or ["IR Lead", "Business Owner"]
            reasons.append(f"escalated to two_person: {target.key()} is absent from the business context map")

    # protections: any protected target escalates the whole plan
    for a in actions:
        why = _protected(a.target, policy, ctx)
        if why:
            authority = _escalate(authority, policy.protections.escalate_to)
            approvers = approvers or ["IR Lead", "CISO"]
            reasons.append(f"escalated to {authority.value}: {why}")

    radius = _radius([a.target for a in actions], ctx)
    # ceilings: count targets per type against the tier's accepted scope
    targets_by_type: dict[str, set[str]] = {}
    for a in actions:
        targets_by_type.setdefault(a.target.type.value, set()).add(a.target.key())
    for etype, targets in targets_by_type.items():
        n = len(targets)
        lim = tier.ceiling.limit_for(etype)
        if n > lim:
            radius.over_ceiling.append(f"{n} {etype}(s) > accepted ceiling {lim}")
    if radius.over_ceiling and authority == Authority.AUTOMATIC:
        authority = Authority.SINGLE_APPROVER
        approvers = approvers or ["IR Lead"]
        reasons.append(
            "escalated to single_approver: blast radius exceeds pre-accepted ceiling ("
            + "; ".join(radius.over_ceiling)
            + ")"
        )
    if crit_at_least(radius.max_criticality, "crown_jewel") and authority == Authority.AUTOMATIC:
        authority = Authority.TWO_PERSON
        approvers = approvers or ["IR Lead", "Business Owner"]
        reasons.append("escalated to two_person: a crown-jewel service is in the blast radius")

    for a in actions:
        a.reason += f" | authority={authority.value}"
    return Plan(subject, tier, authority, actions, radius, reasons, approvers)


def _radius(entities: list[Entity], ctx: BusinessContext) -> BlastRadius:
    services = sorted({ctx.service(e) for e in entities if ctx.service(e)})
    owners = sorted({ctx.owner(e) for e in entities if ctx.owner(e)})
    crits = [ctx.criticality(e) for e in entities] or ["low"]
    from .context import CRITICALITY_ORDER

    maxc = max(crits, key=lambda c: CRITICALITY_ORDER.index(c) if c in CRITICALITY_ORDER else 0)
    return BlastRadius(entities=entities, services=services, max_criticality=maxc, owners=owners)
