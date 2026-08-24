"""Microsoft Entra ID adapter (Microsoft Graph, application permissions).

Env: ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET
Graph permissions needed: User.EnableDisableAccount.All + User.Read.All (disable),
User.RevokeSessions.All (revoke), Application.ReadWrite.All (service principals).

Endpoints (official, documented):
  POST  /v1.0/users/{id}/revokeSignInSessions
  PATCH /v1.0/users/{id}                      {"accountEnabled": false}
  PATCH /v1.0/servicePrincipals/{id}          {"accountEnabled": false}
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import quote

import httpx

from ..models import Action, ActionResult, EntityType, Verb
from .base import Adapter

GRAPH = "https://graph.microsoft.com/v1.0"


class EntraAdapter(Adapter):
    name = "entra"
    platform_aliases = ("azuread", "microsoft", "m365")
    supported: ClassVar[set[Verb]] = {
        Verb.REVOKE_SESSIONS,
        Verb.DISABLE_USER,
        Verb.DISABLE_SERVICE_PRINCIPAL,
    }

    def __init__(self, token_provider=None):
        self._token_provider = token_provider or self._client_credentials_token

    def _client_credentials_token(self, scope="https://graph.microsoft.com/.default") -> str:
        tenant = self.env("ENTRA_TENANT_ID")
        data = {
            "client_id": self.env("ENTRA_CLIENT_ID"),
            "client_secret": self.env("ENTRA_CLIENT_SECRET"),
            "scope": scope,
            "grant_type": "client_credentials",
        }
        r = httpx.post(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", data=data, timeout=20)
        r.raise_for_status()
        return r.json()["access_token"]

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token_provider()}", "Content-Type": "application/json"}

    def execute(self, action: Action, dry_run: bool = True) -> ActionResult:
        uid = quote(action.target.id, safe="")
        if action.verb == Verb.REVOKE_SESSIONS and action.target.type == EntityType.USER:
            url, method, body = f"{GRAPH}/users/{uid}/revokeSignInSessions", "POST", None
        elif action.verb == Verb.DISABLE_USER and action.target.type == EntityType.USER:
            url, method, body = f"{GRAPH}/users/{uid}", "PATCH", {"accountEnabled": False}
        elif (
            action.verb == Verb.DISABLE_SERVICE_PRINCIPAL
            and action.target.type == EntityType.SERVICE_PRINCIPAL
        ):
            url, method, body = f"{GRAPH}/servicePrincipals/{uid}", "PATCH", {"accountEnabled": False}
        else:
            return self._unsupported(action, dry_run)
        if dry_run:
            return self._result(action, True, method, url, body)
        try:
            headers = self._headers()
        except (RuntimeError, httpx.HTTPError, KeyError, ValueError) as e:
            return self._result(action, False, method, url, body, ok=False, detail=str(e))
        return self._send(action, method, url, headers, body)

    def revert(self, action: Action, dry_run: bool = True) -> ActionResult:
        uid = quote(action.target.id, safe="")
        if action.verb == Verb.DISABLE_USER and action.target.type == EntityType.USER:
            url, method, body = f"{GRAPH}/users/{uid}", "PATCH", {"accountEnabled": True}
        elif (
            action.verb == Verb.DISABLE_SERVICE_PRINCIPAL
            and action.target.type == EntityType.SERVICE_PRINCIPAL
        ):
            url, method, body = f"{GRAPH}/servicePrincipals/{uid}", "PATCH", {"accountEnabled": True}
        else:
            return ActionResult(
                action=action,
                adapter=self.name,
                dry_run=dry_run,
                ok=True,
                detail="nothing to revert (session revocation is one-way)",
            )
        if dry_run:
            return self._result(
                action, True, method, url, body, detail=f"DRY-RUN revert would {method} {url}"
            )
        try:
            headers = self._headers()
        except (RuntimeError, httpx.HTTPError, KeyError, ValueError) as e:
            return self._result(action, False, method, url, body, ok=False, detail=str(e))
        return self._send(action, method, url, headers, body)
