"""Business context map: what runs where, how critical it is, who owns it.

This is what lets the engine answer "if I isolate this host, what breaks?" before it acts.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml
from pydantic import Field, field_validator

from ..models import Entity, StrictModel

CRITICALITY_ORDER = ["unknown", "low", "standard", "high", "crown_jewel"]


class Asset(StrictModel):
    id: str = Field(min_length=1)  # hostname / UPN / account id, glob allowed
    type: str = Field(min_length=1)  # user | host | cloud_account | service_principal | backup_vault
    criticality: str = "standard"
    service: str = ""  # business service it supports
    owner: str = ""  # accountable business owner
    platform: str = ""  # adapter name

    @field_validator("criticality")
    @classmethod
    def _known_criticality(cls, value: str) -> str:
        if value not in CRITICALITY_ORDER[1:]:
            raise ValueError("asset criticality must be low, standard, high, or crown_jewel")
        return value


class BusinessContext(StrictModel):
    organization: str = ""
    assets: list[Asset] = Field(default_factory=list)
    services: dict[str, dict] = Field(default_factory=dict)  # service -> {criticality, owner, rto_hours}

    def lookup(self, entity: Entity) -> Asset | None:
        for a in self.assets:
            if a.type == entity.type.value and fnmatch.fnmatch(entity.id.lower(), a.id.lower()):
                return a
        return None

    def criticality(self, entity: Entity) -> str:
        a = self.lookup(entity)
        return a.criticality if a else "unknown"

    def recognizes(self, entity: Entity) -> bool:
        return self.lookup(entity) is not None

    def service(self, entity: Entity) -> str:
        a = self.lookup(entity)
        return a.service if a else ""

    def owner(self, entity: Entity) -> str:
        a = self.lookup(entity)
        return a.owner if a else ""


def load_context(path: Path | None) -> BusinessContext:
    if path is None or not Path(path).is_file():
        return BusinessContext()
    with open(path, encoding="utf-8") as f:
        return BusinessContext.model_validate(yaml.safe_load(f) or {})


def crit_at_least(value: str, floor: str) -> bool:
    try:
        return CRITICALITY_ORDER.index(value) >= CRITICALITY_ORDER.index(floor)
    except ValueError:
        return False
