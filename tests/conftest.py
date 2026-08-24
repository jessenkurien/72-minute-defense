from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from seventytwo.engine.audit import AuditLog
from seventytwo.engine.context import load_context
from seventytwo.models import Entity, EntityType, PrecursorEvent
from seventytwo.policy import load_policy
from seventytwo.scoring import load_catalog

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def policy():
    return load_policy(ROOT / "policy" / "containment-authority.yaml")


@pytest.fixture
def ctx():
    return load_context(ROOT / "policy" / "business-context.yaml")


@pytest.fixture
def catalog():
    return load_catalog()


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


def user(uid="j.doe@example.com", platform="entra") -> Entity:
    return Entity(type=EntityType.USER, id=uid, platform=platform)


def host(hid="ws-4471", platform="defender") -> Entity:
    return Entity(type=EntityType.HOST, id=hid, platform=platform)


def ev(signal, minute, entity, related=(), confidence=1.0, i=None) -> PrecursorEvent:
    return PrecursorEvent(
        id=i or f"{signal}-{minute}",
        ts=T0 + timedelta(minutes=minute),
        signal=signal,
        entity=entity,
        related=list(related),
        source="test",
        confidence=confidence,
    )
