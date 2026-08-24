"""Adapter contract. One adapter per platform; each maps vendor-neutral verbs onto official APIs.

Rules every adapter follows:
  * `dry_run=True` performs no state-changing network call; it returns a request preview
    (URL, method, body with secrets redacted when known) so the plan is reviewable.
  * Credentials come from environment variables only; never from the policy or the audit log.
  * `revert()` undoes a reversible action (unisolate, unsuspend, detach quarantine policy).
  * Adapters raise nothing to the executor: every failure is an ActionResult(ok=False).
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import ClassVar
from urllib.parse import urlsplit

import httpx

from ..models import Action, ActionResult, Entity, Verb


class Adapter(ABC):
    name: ClassVar[str] = "base"
    platform_aliases: ClassVar[tuple[str, ...]] = ()
    supported: ClassVar[set[Verb]] = set()

    def supports(self, verb: Verb) -> bool:
        return verb in self.supported

    @abstractmethod
    def execute(self, action: Action, dry_run: bool = True) -> ActionResult: ...

    def revert(self, action: Action, dry_run: bool = True) -> ActionResult:
        return ActionResult(
            action=action, adapter=self.name, dry_run=dry_run, ok=False, detail="revert not implemented"
        )

    # ---- helpers ---------------------------------------------------------------
    def _unsupported(self, action: Action, dry_run: bool) -> ActionResult:
        return ActionResult(
            action=action,
            adapter=self.name,
            dry_run=dry_run,
            ok=False,
            detail=f"{self.name} does not implement {action.verb.value}",
        )

    def _result(
        self,
        action: Action,
        dry_run: bool,
        method: str,
        url: str,
        body: dict | None = None,
        ok: bool = True,
        detail: str = "",
    ) -> ActionResult:
        req = {"method": method, "url": url, "body": body or {}}
        if dry_run:
            return ActionResult(
                action=action,
                adapter=self.name,
                dry_run=True,
                ok=True,
                detail=detail or f"DRY-RUN would {method} {url}",
                request=req,
            )
        return ActionResult(
            action=action, adapter=self.name, dry_run=False, ok=ok, detail=detail, request=req
        )

    def _send(
        self,
        action: Action,
        method: str,
        url: str,
        headers: dict,
        body: dict | None = None,
        ok_codes=(200, 201, 202, 204),
    ) -> ActionResult:
        try:
            with httpx.Client(timeout=20) as c:
                r = c.request(method, url, headers=headers, json=body)
            ok = r.status_code in ok_codes
            detail = f"{r.status_code} {r.text[:200]}" if not ok else f"{r.status_code} ok"
            return self._result(action, False, method, url, body, ok=ok, detail=detail)
        except httpx.HTTPError as e:
            return self._result(action, False, method, url, body, ok=False, detail=f"http error: {e}")

    @staticmethod
    def env(name: str, required: bool = True) -> str:
        v = os.environ.get(name, "")
        if required and not v:
            raise RuntimeError(f"missing environment variable {name}")
        return v

    @staticmethod
    def https_base(value: str, label: str) -> str:
        """Validate configurable vendor bases to prevent accidental cleartext or credential URLs."""
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise RuntimeError(f"{label} must be an HTTPS origin without embedded credentials")
        if parsed.query or parsed.fragment:
            raise RuntimeError(f"{label} must not include a query string or fragment")
        return value.rstrip("/")


def resolve_adapter(target: Entity, adapters: dict[str, Adapter]) -> Adapter | None:
    """Pick the adapter for an entity by its platform tag, else the first that supports the type."""
    if target.platform:
        platform = target.platform.casefold()
        for a in adapters.values():
            if platform == a.name.casefold() or platform in {
                alias.casefold() for alias in a.platform_aliases
            }:
                return a
        return None
    return next(iter(adapters.values()), None)
