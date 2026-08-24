"""Mock adapter: used by `72md rehearse`, tests, and any platform without a real adapter yet.

Records every action so a rehearsal can show *what the engine planned* without a tenant.
"""

from __future__ import annotations

from typing import ClassVar

from ..models import Action, ActionResult, Verb
from .base import Adapter


class MockAdapter(Adapter):
    name = "mock"
    platform_aliases = ("entra", "okta", "defender", "crowdstrike", "aws", "azure", "gcp", "backup", "*")
    supported: ClassVar[set[Verb]] = set(Verb)

    def __init__(self, fail_verbs: set[Verb] | None = None, latency_seconds: float = 0.0):
        self.calls: list[Action] = []
        self.fail_verbs = fail_verbs or set()
        self.latency_seconds = latency_seconds

    def execute(self, action: Action, dry_run: bool = True) -> ActionResult:
        self.calls.append(action)
        ok = action.verb not in self.fail_verbs
        return ActionResult(
            action=action,
            adapter=self.name,
            dry_run=dry_run,
            ok=ok,
            detail=("simulated " + ("ok" if ok else "failure"))
            + f" ({action.verb.value} → {action.target.key()})",
            request={
                "method": "MOCK",
                "url": f"mock://{action.target.platform or 'any'}/{action.verb.value}",
                "body": {"target": action.target.id},
            },
        )

    def revert(self, action: Action, dry_run: bool = True) -> ActionResult:
        return ActionResult(
            action=action, adapter=self.name, dry_run=dry_run, ok=True, detail="simulated revert"
        )
