"""Shared, vendor-neutral data models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    """Reject misspelled fields instead of silently weakening a safety decision."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EntityType(str, Enum):
    USER = "user"
    HOST = "host"
    SERVICE_PRINCIPAL = "service_principal"
    CLOUD_ACCOUNT = "cloud_account"
    BACKUP_VAULT = "backup_vault"


class Entity(StrictModel):
    type: EntityType
    id: str = Field(min_length=1)  # vendor-neutral id (UPN, hostname, account id...)
    platform: str = ""  # which adapter owns it: entra, okta, defender, crowdstrike, aws...
    display: str = ""

    def key(self) -> str:
        return f"{self.type.value}:{self.id}"


class Stage(str, Enum):
    """Ransomware precursor chain, in order. Distance-to-impact counts remaining stages."""

    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    DEFENSE_EVASION = "defense_evasion"
    EXFIL_STAGING = "exfil_staging"
    IMPACT = "impact"


STAGE_ORDER = list(Stage)


class PrecursorEvent(StrictModel):
    """One normalized detection from any source (SIEM, XDR, cloud log)."""

    id: str = Field(min_length=1)
    ts: datetime
    signal: str  # key into the precursor catalog, e.g. "backup_tamper"
    entity: Entity
    related: list[Entity] = Field(default_factory=list)  # e.g. the host a user logged in from
    source: str = "unknown"  # sentinel, splunk, falcon, guardduty...
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)  # multiplies the catalog weight
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ts")
    @classmethod
    def _timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event timestamp must include a timezone")
        return value.astimezone(timezone.utc)


class Verb(str, Enum):
    """Vendor-neutral containment actions. Adapters map these onto vendor APIs."""

    REVOKE_SESSIONS = "identity.revoke_sessions"
    REQUIRE_MFA_RESET = "identity.require_mfa_reset"
    DISABLE_USER = "identity.disable_user"
    DISABLE_SERVICE_PRINCIPAL = "identity.disable_service_principal"
    ISOLATE_HOST = "endpoint.isolate_host"
    QUARANTINE_ACCOUNT = "cloud.quarantine_account"
    DEACTIVATE_KEYS = "cloud.deactivate_keys"
    LOCK_BACKUP_VAULT = "backup.lock_vault"
    NOTIFY = "notify"


REVERSIBLE = {
    Verb.REVOKE_SESSIONS: True,
    Verb.REQUIRE_MFA_RESET: True,
    Verb.DISABLE_USER: True,
    Verb.DISABLE_SERVICE_PRINCIPAL: True,
    Verb.ISOLATE_HOST: True,
    Verb.QUARANTINE_ACCOUNT: True,
    # The AWS adapter applies a governance-mode vault lock, which an authorized administrator
    # can remove. It deliberately does not create an irreversible compliance-mode lock.
    Verb.DEACTIVATE_KEYS: True,
    Verb.LOCK_BACKUP_VAULT: True,
    Verb.NOTIFY: False,
}

# Verbs that actually stop an attacker (vs. friction that merely slows them).
CONTAINING = {
    Verb.DISABLE_USER,
    Verb.DISABLE_SERVICE_PRINCIPAL,
    Verb.ISOLATE_HOST,
    Verb.QUARANTINE_ACCOUNT,
    Verb.DEACTIVATE_KEYS,
}

VERB_TARGETS = {
    Verb.REVOKE_SESSIONS: {EntityType.USER, EntityType.SERVICE_PRINCIPAL},
    Verb.REQUIRE_MFA_RESET: {EntityType.USER},
    Verb.DISABLE_USER: {EntityType.USER},
    Verb.DISABLE_SERVICE_PRINCIPAL: {EntityType.SERVICE_PRINCIPAL},
    Verb.ISOLATE_HOST: {EntityType.HOST},
    Verb.QUARANTINE_ACCOUNT: {EntityType.CLOUD_ACCOUNT},
    # Static access keys belong to IAM users. Workload roles are handled through session
    # revocation or service-principal disablement instead.
    Verb.DEACTIVATE_KEYS: {EntityType.USER},
    Verb.LOCK_BACKUP_VAULT: {EntityType.BACKUP_VAULT},
    Verb.NOTIFY: set(EntityType),
}


class Action(StrictModel):
    verb: Verb
    target: Entity
    reason: str = ""
    tier: str = ""
    reversible: bool = True
    review_after_minutes: int | None = Field(default=None, ge=1)


class ActionResult(StrictModel):
    action: Action
    adapter: str
    dry_run: bool
    ok: bool
    detail: str = ""
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request: dict[str, Any] = Field(default_factory=dict)  # what would be / was sent (no secrets)


class Authority(str, Enum):
    AUTOMATIC = "automatic"  # SOC platform may execute without a human
    SINGLE_APPROVER = "single_approver"
    TWO_PERSON = "two_person"
    MANUAL_ONLY = "manual_only"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
