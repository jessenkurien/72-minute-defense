"""Platform adapters. `build_adapters()` wires the set named in config or all-mock for rehearsal."""

from __future__ import annotations

from .aws import AWSAdapter
from .base import Adapter, resolve_adapter
from .crowdstrike import CrowdStrikeAdapter
from .defender import DefenderAdapter
from .entra import EntraAdapter
from .mock import MockAdapter
from .okta import OktaAdapter

REAL = {
    "entra": EntraAdapter,
    "defender": DefenderAdapter,
    "okta": OktaAdapter,
    "crowdstrike": CrowdStrikeAdapter,
    "aws": AWSAdapter,
}


def build_adapters(names: list[str] | None, mock: bool = False) -> dict[str, Adapter]:
    if mock or not names:
        return {"mock": MockAdapter()}
    out: dict[str, Adapter] = {}
    for n in names:
        if n == "mock":
            out["mock"] = MockAdapter()
        elif n in REAL:
            out[n] = REAL[n]()
        else:
            raise ValueError(f"unknown adapter '{n}'; known: {', '.join(REAL)}, mock")
    return out


__all__ = [
    "REAL",
    "AWSAdapter",
    "Adapter",
    "CrowdStrikeAdapter",
    "DefenderAdapter",
    "EntraAdapter",
    "MockAdapter",
    "OktaAdapter",
    "build_adapters",
    "resolve_adapter",
]
