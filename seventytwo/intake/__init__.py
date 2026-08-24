"""Alert intake: normalize vendor payloads into PrecursorEvents.

Each normalizer is deliberately small and mapping-driven so a SOC can extend it with their own
rule names without touching the engine. Unknown rule names are dropped (and reported), never
guessed: an unmapped alert must not silently raise or lower a score.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ..models import Entity, EntityType, PrecursorEvent

_MAP = Path(__file__).resolve().parent.parent / "data" / "intake_map.yaml"


def load_map(path: Path | None = None) -> dict[str, dict[str, str]]:
    with open(path or _MAP, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _ts(v: Any) -> datetime:
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    s = str(v).replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize(
    fmt: str, payload: dict | list, mapping: dict | None = None, default_platform: dict | None = None
) -> tuple[list[PrecursorEvent], list[str]]:
    """Returns (events, unmapped_rule_names)."""
    mapping = mapping or load_map()
    default_platform = default_platform or {}
    items = payload if isinstance(payload, list) else [payload]
    events, unmapped = [], []
    for it in items:
        fn = {
            "generic": _generic,
            "sentinel": _sentinel,
            "splunk": _splunk,
            "falcon": _falcon,
            "guardduty": _guardduty,
        }.get(fmt)
        if fn is None:
            raise ValueError(f"unknown intake format '{fmt}'")
        ev, miss = fn(it, mapping.get(fmt, {}), default_platform)
        events.extend(ev)
        unmapped.extend(miss)
    return events, unmapped


def _entity(t: str, i: str, platform: str = "") -> Entity:
    return Entity(type=EntityType(t), id=i, platform=platform)


def _generic(it: dict, m: dict, dp: dict):
    """Already in our shape: {id, ts, signal, entity:{type,id,platform}, related:[...], source, confidence}"""
    return [PrecursorEvent.model_validate(it)], []


def _sentinel(it: dict, m: dict, dp: dict):
    """Microsoft Sentinel incident/alert (Logic App or REST export). Uses AlertName → signal map,
    Entities[] for user/host."""
    name = it.get("AlertName") or it.get("properties", {}).get("alertDisplayName", "")
    sig = m.get(name)
    if not sig:
        return [], [name or "<no AlertName>"]
    ents = it.get("Entities") or it.get("properties", {}).get("relatedEntities") or []
    if isinstance(ents, str):
        ents = json.loads(ents)
    users = [e for e in ents if str(e.get("Type", e.get("kind", ""))).lower() == "account"]
    hosts = [e for e in ents if str(e.get("Type", e.get("kind", ""))).lower() == "host"]
    primary = None
    related = []
    for u in users:
        upn = (
            u.get("UPNSuffix")
            and f"{u.get('Name')}@{u.get('UPNSuffix')}"
            or u.get("Name")
            or u.get("aadUserId", "")
        )
        related.append(_entity("user", upn, dp.get("user", "entra")))
    for h in hosts:
        related.append(
            _entity(
                "host",
                h.get("MdatpDeviceId") or h.get("HostName") or h.get("hostName", ""),
                dp.get("host", "defender"),
            )
        )
    if not related:
        return [], [f"{name}: no entities"]
    primary = related.pop(0)
    ev = PrecursorEvent(
        id=str(it.get("SystemAlertId") or it.get("name") or f"sentinel-{name}-{primary.id}"),
        ts=_ts(
            it.get("TimeGenerated") or it.get("StartTime") or it.get("properties", {}).get("createdTimeUtc")
        ),
        signal=sig,
        entity=primary,
        related=related,
        source="sentinel",
        confidence=float(it.get("confidence", 1.0)),
        raw={"AlertName": name},
    )
    return [ev], []


def _splunk(it: dict, m: dict, dp: dict):
    """Splunk ES notable (webhook alert action): result.search_name / rule_name, user, dest/host."""
    r = it.get("result", it)
    name = r.get("search_name") or r.get("rule_name") or it.get("search_name", "")
    sig = m.get(name)
    if not sig:
        return [], [name or "<no search_name>"]
    related = []
    if r.get("user"):
        related.append(_entity("user", r["user"], dp.get("user", "okta")))
    if r.get("dest") or r.get("host"):
        related.append(_entity("host", r.get("dest") or r.get("host"), dp.get("host", "crowdstrike")))
    if not related:
        return [], [f"{name}: no user/dest"]
    primary = related.pop(0)
    ev = PrecursorEvent(
        id=str(it.get("sid") or r.get("event_id") or f"splunk-{name}-{primary.id}"),
        ts=_ts(r.get("_time") or it.get("_time")),
        signal=sig,
        entity=primary,
        related=related,
        source="splunk",
        raw={"search_name": name},
    )
    return [ev], []


def _falcon(it: dict, m: dict, dp: dict):
    """CrowdStrike Falcon detection (event stream / streaming API): tactic/technique or pattern name."""
    name = (
        it.get("DetectName")
        or it.get("detection_name")
        or it.get("event", {}).get("DetectName")
        or it.get("technique", "")
    )
    sig = m.get(name)
    if not sig:
        return [], [name or "<no DetectName>"]
    e = it.get("event", it)
    related = []
    if e.get("UserName"):
        related.append(_entity("user", e["UserName"], dp.get("user", "okta")))
    aid = e.get("SensorId") or e.get("device_id") or e.get("aid")
    if aid:
        related.append(_entity("host", aid, "crowdstrike"))
    if not related:
        return [], [f"{name}: no user/aid"]
    primary = related.pop(0)
    ts = e.get("ProcessStartTime") or e.get("timestamp") or it.get("metadata", {}).get("eventCreationTime")
    ev = PrecursorEvent(
        id=str(e.get("DetectId") or f"falcon-{name}-{primary.id}"),
        ts=_ts(ts if ts else datetime.now(timezone.utc).isoformat()),
        signal=sig,
        entity=primary,
        related=related,
        source="falcon",
        raw={"DetectName": name},
    )
    return [ev], []


def _guardduty(it: dict, m: dict, dp: dict):
    """AWS GuardDuty finding (EventBridge): detail.type → signal, resource accessKeyDetails.userName / accountId."""
    d = it.get("detail", it)
    ftype = d.get("type", "")
    sig = m.get(ftype)
    if not sig:
        return [], [ftype or "<no type>"]
    res = d.get("resource", {})
    akd = res.get("accessKeyDetails", {})
    related = []
    if akd.get("userName"):
        related.append(
            _entity(
                "service_principal" if akd.get("userType") == "AssumedRole" else "user",
                akd["userName"],
                "aws",
            )
        )
    if d.get("accountId"):
        related.append(_entity("cloud_account", d["accountId"], "aws"))
    if not related:
        return [], [f"{ftype}: no principal"]
    primary = related.pop(0)
    ev = PrecursorEvent(
        id=str(d.get("id") or f"gd-{ftype}-{primary.id}"),
        ts=_ts(d.get("updatedAt") or d.get("createdAt")),
        signal=sig,
        entity=primary,
        related=related,
        source="guardduty",
        confidence=min(1.0, float(d.get("severity", 5)) / 8.0),
        raw={"type": ftype},
    )
    return [ev], []
