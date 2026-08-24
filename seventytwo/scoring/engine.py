"""Precursor chain scoring.

A score is not a checklist. Missing one alert lowers the score; it doesn't zero it.

score(entity) = min(100, Σ strongest_weight_per_distinct_signal × stage_bonus)
  * decay:        exponential half-life per signal (catalog `decay` minutes)
  * stage_bonus:  +10% per distinct stage already seen (a chain is worse than repeats of one stage)
  * critical:     a critical signal at confidence ≥0.8 marks the entity critical; policy may set a tier floor

distance_to_impact = number of chain stages after the deepest stage seen (0 = impact observed)

Entities are clustered: a user and the host they acted from share evidence, so the score of a
cluster is the score of its combined events. This is what turns three mediums nobody escalates
into one authorized action.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml

from ..models import STAGE_ORDER, Entity, PrecursorEvent, Stage

_DATA = Path(__file__).resolve().parent.parent / "data" / "precursors.yaml"
CRITICAL_CONFIDENCE_FLOOR = 0.8


@dataclass
class Signal:
    key: str
    stage: Stage
    weight: float
    technique: str
    decay: float
    critical: bool
    desc: str


@dataclass
class Catalog:
    signals: dict[str, Signal]

    def get(self, key: str) -> Signal:
        if key not in self.signals:
            raise KeyError(f"unknown precursor signal: {key}")
        return self.signals[key]


def load_catalog(path: Path | None = None) -> Catalog:
    with open(path or _DATA, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    sigs = {}
    for k, v in data["signals"].items():
        sigs[k] = Signal(
            k,
            Stage(v["stage"]),
            float(v["weight"]),
            v.get("technique", ""),
            float(v.get("decay", 360)),
            bool(v.get("critical", False)),
            v.get("desc", ""),
        )
    return Catalog(sigs)


@dataclass
class EntityScore:
    entity: Entity
    cluster: list[Entity]
    score: float
    critical: bool
    stages_seen: list[Stage]
    distance_to_impact: int
    contributing: list[tuple[str, float]]  # (signal, effective weight)
    first_seen: datetime
    last_seen: datetime
    events: list[PrecursorEvent] = field(default_factory=list)

    @property
    def deepest_stage(self) -> Stage | None:
        return max(self.stages_seen, key=STAGE_ORDER.index) if self.stages_seen else None


def _decay(age_minutes: float, half_life: float) -> float:
    if age_minutes <= 0:
        return 1.0
    return math.pow(0.5, age_minutes / half_life)


def _clusters(events: list[PrecursorEvent]) -> list[set[str]]:
    """Union-find over entity keys: an event links its entity with every related entity."""
    parent: dict[str, str] = {}

    def find(k):
        parent.setdefault(k, k)
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for e in events:
        find(e.entity.key())
        for r in e.related:
            union(e.entity.key(), r.key())
    groups: dict[str, set[str]] = {}
    for k in list(parent):
        groups.setdefault(find(k), set()).add(k)
    return list(groups.values())


def _deduplicate(events: list[PrecursorEvent]) -> list[PrecursorEvent]:
    """Ignore exact delivery retries and reject conflicting reuse of a source event id."""
    seen: dict[tuple[str, str], PrecursorEvent] = {}
    for event in events:
        key = (event.source, event.id)
        if key in seen:
            if seen[key].model_dump(mode="json") != event.model_dump(mode="json"):
                raise ValueError(f"conflicting duplicate event id: {event.source}:{event.id}")
            continue
        seen[key] = event
    return list(seen.values())


def score_events(
    events: list[PrecursorEvent], catalog: Catalog, now: datetime | None = None
) -> list[EntityScore]:
    if not events:
        return []
    events = _deduplicate(events)
    now = now or max(e.ts for e in events)
    by_key: dict[str, Entity] = {}
    for e in events:
        by_key[e.entity.key()] = e.entity
        for r in e.related:
            by_key.setdefault(r.key(), r)

    results: list[EntityScore] = []
    for group in _clusters(events):
        evs = [e for e in events if e.entity.key() in group]
        stages: set[Stage] = set()
        strongest: dict[str, float] = {}
        critical = False
        for e in evs:
            sig = catalog.get(e.signal)
            age = (now - e.ts).total_seconds() / 60.0
            eff = sig.weight * e.confidence * _decay(age, sig.decay)
            strongest[e.signal] = max(strongest.get(e.signal, 0.0), eff)
            stages.add(sig.stage)
            critical = critical or (sig.critical and e.confidence >= CRITICAL_CONFIDENCE_FLOOR)
        contributing = [(signal, round(weight, 1)) for signal, weight in strongest.items()]
        total = sum(strongest.values())
        total *= 1 + 0.10 * max(0, len(stages) - 1)
        score = round(min(100.0, total), 1)
        deepest = max(stages, key=STAGE_ORDER.index)
        distance = len(STAGE_ORDER) - 1 - STAGE_ORDER.index(deepest)
        # primary entity = the user if present (identity drives 89% of intrusions), else first seen
        prio = {"user": 0, "service_principal": 1, "host": 2, "cloud_account": 3, "backup_vault": 4}
        primary = min((by_key[k] for k in group), key=lambda e: (prio.get(e.type.value, 9), e.id))
        results.append(
            EntityScore(
                entity=primary,
                cluster=[by_key[k] for k in sorted(group)],
                score=score,
                critical=critical,
                stages_seen=sorted(stages, key=STAGE_ORDER.index),
                distance_to_impact=distance,
                contributing=sorted(contributing, key=lambda c: -c[1]),
                first_seen=min(e.ts for e in evs),
                last_seen=max(e.ts for e in evs),
                events=evs,
            )
        )
    return sorted(results, key=lambda r: -r.score)
