"""Okta adapter (official Users API).

Env: OKTA_ORG_URL (https://acme.okta.com), OKTA_API_TOKEN (SSWS) — or an OAuth bearer via OKTA_BEARER.

Endpoints:
  DELETE /api/v1/users/{id}/sessions?oauthTokens=true     revoke all sessions + OAuth/OIDC tokens
  POST   /api/v1/users/{id}/lifecycle/suspend              reversible disable
  POST   /api/v1/users/{id}/lifecycle/unsuspend
  POST   /api/v1/users/{id}/lifecycle/reset_factors        MFA reset
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import quote

from ..models import Action, ActionResult, EntityType, Verb
from .base import Adapter


class OktaAdapter(Adapter):
    name = "okta"
    platform_aliases = ()
    supported: ClassVar[set[Verb]] = {Verb.REVOKE_SESSIONS, Verb.DISABLE_USER, Verb.REQUIRE_MFA_RESET}

    def _base(self) -> str:
        return self.https_base(self.env("OKTA_ORG_URL"), "OKTA_ORG_URL")

    def _headers(self) -> dict:
        bearer = self.env("OKTA_BEARER", required=False)
        auth = f"Bearer {bearer}" if bearer else f"SSWS {self.env('OKTA_API_TOKEN')}"
        return {"Authorization": auth, "Accept": "application/json", "Content-Type": "application/json"}

    def execute(self, action: Action, dry_run: bool = True) -> ActionResult:
        if action.target.type != EntityType.USER:
            return self._unsupported(action, dry_run)
        uid = quote(action.target.id, safe="")
        try:
            configured = self.env("OKTA_ORG_URL", required=False)
            base = self.https_base(configured, "OKTA_ORG_URL") if configured else "https://<OKTA_ORG_URL>"
            if not dry_run and not configured:
                raise RuntimeError("missing environment variable OKTA_ORG_URL")
        except RuntimeError as e:
            return ActionResult(action=action, adapter=self.name, dry_run=dry_run, ok=False, detail=str(e))
        if action.verb == Verb.REVOKE_SESSIONS:
            method, url, body = "DELETE", f"{base}/api/v1/users/{uid}/sessions?oauthTokens=true", None
        elif action.verb == Verb.DISABLE_USER:
            method, url, body = "POST", f"{base}/api/v1/users/{uid}/lifecycle/suspend", None
        elif action.verb == Verb.REQUIRE_MFA_RESET:
            method, url, body = "POST", f"{base}/api/v1/users/{uid}/lifecycle/reset_factors", None
        else:
            return self._unsupported(action, dry_run)
        if dry_run:
            return self._result(action, True, method, url, body)
        try:
            headers = self._headers()
        except RuntimeError as e:
            return self._result(action, False, method, url, body, ok=False, detail=str(e))
        return self._send(action, method, url, headers, body)

    def revert(self, action: Action, dry_run: bool = True) -> ActionResult:
        if action.verb != Verb.DISABLE_USER or action.target.type != EntityType.USER:
            return ActionResult(
                action=action, adapter=self.name, dry_run=dry_run, ok=True, detail="nothing to revert"
            )
        base = "https://<OKTA_ORG_URL>" if dry_run else self._base()
        uid = quote(action.target.id, safe="")
        url = f"{base}/api/v1/users/{uid}/lifecycle/unsuspend"
        if dry_run:
            return self._result(action, True, "POST", url, detail=f"DRY-RUN revert would POST {url}")
        try:
            headers = self._headers()
        except RuntimeError as e:
            return self._result(action, False, "POST", url, ok=False, detail=str(e))
        return self._send(action, "POST", url, headers)
