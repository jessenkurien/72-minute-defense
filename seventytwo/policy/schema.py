"""Containment Authority Policy — digest-attested, versioned delegation of authority.

This is the artifact leadership signs in a calm afternoon so the SOC does not need a
bridge call at 2 a.m. Everything the engine is allowed to do is derived from it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from typing import Any

import yaml
from pydantic import Field, field_validator, model_validator

from ..models import Authority, StrictModel, Verb


class ScopeCeiling(StrictModel):
    """Maximum blast radius the business has accepted *in advance* for automatic action."""

    users: int = Field(default=0, ge=0)
    hosts: int = Field(default=0, ge=0)
    cloud_accounts: int = Field(default=0, ge=0)
    service_principals: int = Field(default=0, ge=0)
    backup_vaults: int = Field(default=0, ge=0)

    def limit_for(self, entity_type: str) -> int:
        return {
            "user": self.users,
            "host": self.hosts,
            "cloud_account": self.cloud_accounts,
            "service_principal": self.service_principals,
            "backup_vault": self.backup_vaults,
        }.get(entity_type, 0)


class Tier(StrictModel):
    name: str = Field(min_length=1)
    threshold: int = Field(ge=0, le=100)
    actions: list[Verb]
    authority: Authority
    approver_roles: list[str] = Field(default_factory=list)
    ceiling: ScopeCeiling = Field(default_factory=ScopeCeiling)
    mandatory_review_minutes: int | None = Field(default=None, ge=1)
    accepted_impact: str = ""  # plain-language statement the business signed
    notify: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _approvers_required(self):
        if self.authority in (Authority.SINGLE_APPROVER, Authority.TWO_PERSON) and not self.approver_roles:
            raise ValueError(f"tier {self.name}: {self.authority.value} requires approver_roles")
        if self.authority == Authority.AUTOMATIC and self.approver_roles:
            raise ValueError(f"tier {self.name}: automatic authority cannot declare approver_roles")
        return self


class Protection(StrictModel):
    """Entities that never receive automatic action regardless of score."""

    principals: list[str] = Field(default_factory=list)  # UPNs / ids / glob patterns
    hosts: list[str] = Field(default_factory=list)
    criticality_at_least: str | None = None  # e.g. "crown_jewel" from business context
    escalate_to: Authority = Authority.TWO_PERSON

    @field_validator("criticality_at_least")
    @classmethod
    def _known_criticality(cls, value: str | None) -> str | None:
        if value is not None and value not in {"low", "standard", "high", "crown_jewel"}:
            raise ValueError("criticality_at_least must be low, standard, high, or crown_jewel")
        return value


class Attestation(StrictModel):
    """A digest-bound approval record; identity assurance comes from the review system."""

    role: str = Field(min_length=1)
    name: str = Field(min_length=1)
    date: date
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ContainmentPolicy(StrictModel):
    version: int
    organization: str = Field(min_length=1)
    template: bool = False
    effective_from: date
    review_by: date
    attacker_clock_minutes: int = 72
    tiers: list[Tier]
    protections: Protection = Field(default_factory=Protection)
    critical_signals_force_tier: str | None = None  # a single critical signal jumps straight here
    required_attestation_roles: list[str] = Field(default_factory=lambda: ["CISO"])
    attestations: list[Attestation] = Field(default_factory=list)
    notes: str = ""

    @field_validator("tiers")
    @classmethod
    def _tiers_ordered(cls, tiers: list[Tier]) -> list[Tier]:
        if not tiers:
            raise ValueError("at least one tier is required")
        names = [t.name for t in tiers]
        if len(set(names)) != len(names):
            raise ValueError("tier names must be unique")
        thresholds = [t.threshold for t in tiers]
        if thresholds != sorted(thresholds):
            raise ValueError("tiers must be listed in ascending threshold order")
        if len(set(thresholds)) != len(thresholds):
            raise ValueError("tier thresholds must be unique")
        return tiers

    @field_validator("required_attestation_roles")
    @classmethod
    def _required_roles_are_unique(cls, roles: list[str]) -> list[str]:
        if not roles:
            raise ValueError("at least one required attestation role is required")
        if any(not role.strip() for role in roles):
            raise ValueError("required attestation roles cannot be blank")
        if len(set(roles)) != len(roles):
            raise ValueError("required attestation roles must be unique")
        return roles

    @model_validator(mode="after")
    def _policy_relationships(self):
        if self.review_by < self.effective_from:
            raise ValueError("review_by precedes effective_from")
        if self.critical_signals_force_tier:
            self.tier(self.critical_signals_force_tier)
        return self

    # ---- integrity -----------------------------------------------------------
    def canonical_body(self) -> dict[str, Any]:
        """Everything except attestations, JSON-canonicalized for hashing."""
        body = self.model_dump(mode="json", exclude={"attestations"})
        return body

    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(self.canonical_body(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def verify(self) -> tuple[bool, list[str]]:
        """Verify that every required role attested to the current canonical digest.

        This proves that the file and its approval records agree. It does not authenticate the
        people named in the records; deployments must obtain identity assurance from protected
        pull-request review, signed commits, or an external approval system.
        """
        problems: list[str] = []
        d = self.digest()
        current_roles: list[str] = []
        today = datetime.now(timezone.utc).date()
        for s in self.attestations:
            if s.digest != d:
                problems.append(
                    f"attestation by {s.role} ({s.name}) is for a different policy body (stale or changed)"
                )
            else:
                current_roles.append(s.role)
            if s.date > today:
                problems.append(f"attestation by {s.role} ({s.name}) is future-dated")
        for role in self.required_attestation_roles:
            if current_roles.count(role) == 0:
                problems.append(f"missing current attestation from required role: {role}")
            elif current_roles.count(role) > 1:
                problems.append(f"multiple current attestations claim required role: {role}")
        return (not problems), problems

    def arming_problems(self, expected_digest: str | None, on: date | None = None) -> list[str]:
        """Return every reason this policy must not authorize live execution."""
        _, problems = self.verify()
        problems = list(problems)
        today = on or datetime.now(timezone.utc).date()
        if self.template:
            problems.append("template policies are dry-run and rehearsal only")
        if today < self.effective_from:
            problems.append(f"policy is not effective until {self.effective_from.isoformat()}")
        if today > self.review_by:
            problems.append(f"policy review expired on {self.review_by.isoformat()}")
        if not expected_digest:
            problems.append("SEVENTYTWO_POLICY_DIGEST is required as an out-of-band digest pin")
        elif expected_digest.lower() != self.digest():
            problems.append("out-of-band policy digest pin does not match the current policy")
        return problems

    def tier_for_score(self, score: float, critical: bool = False) -> Tier | None:
        """Highest tier whose threshold the score meets. A critical signal sets a *floor*
        (never a cap): the forced tier applies unless the score already earns a higher one."""
        chosen = None
        for t in self.tiers:
            if score >= t.threshold:
                chosen = t
        if critical and self.critical_signals_force_tier:
            forced = self.tier(self.critical_signals_force_tier)
            if chosen is None or forced.threshold > chosen.threshold:
                chosen = forced
        return chosen

    def highest_automatic_below(self, tier: Tier, score: float) -> Tier | None:
        """The best tier the SOC may execute *without* approval while a higher tier awaits it."""
        best = None
        for t in self.tiers:
            if t.threshold < tier.threshold and score >= t.threshold and t.authority == Authority.AUTOMATIC:
                best = t
        return best

    def tier(self, name: str) -> Tier:
        for t in self.tiers:
            if t.name == name:
                return t
        raise KeyError(name)


def load_policy(path) -> ContainmentPolicy:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return ContainmentPolicy.model_validate(data)


def attest(policy: ContainmentPolicy, role: str, name: str, on: date | None = None) -> Attestation:
    """Produce an attestation for the current body; authenticate it in the review system."""
    today = datetime.now(timezone.utc).date()
    return Attestation(role=role, name=name, date=on or today, digest=policy.digest())
