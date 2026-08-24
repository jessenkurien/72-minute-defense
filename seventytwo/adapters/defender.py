"""Microsoft Defender for Endpoint adapter (official Machine Actions API).

Env: ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET  (app permission: Machine.Isolate)

Endpoints:
  POST https://api.security.microsoft.com/api/machines/{machineId}/isolate   {"Comment": ..., "IsolationType": "Full"|"Selective"}
  POST https://api.security.microsoft.com/api/machines/{machineId}/unisolate {"Comment": ...}

Note: where the tenant already runs automatic attack disruption, this adapter is the governed
path for the same isolation primitive, plus the audit trail and mandatory review the policy defines.
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import quote

import httpx

from ..models import Action, ActionResult, EntityType, Verb
from .base import Adapter

API = "https://api.security.microsoft.com/api"


class DefenderAdapter(Adapter):
    name = "defender"
    platform_aliases = ("mde", "defender_for_endpoint")
    supported: ClassVar[set[Verb]] = {Verb.ISOLATE_HOST}

    def __init__(self, token_provider=None, isolation_type: str = "Full"):
        if isolation_type not in {"Full", "Selective"}:
            raise ValueError("isolation_type must be Full or Selective")
        self._token_provider = token_provider or self._token
        self.isolation_type = isolation_type

    def _token(self) -> str:
        tenant = self.env("ENTRA_TENANT_ID")
        data = {
            "client_id": self.env("ENTRA_CLIENT_ID"),
            "client_secret": self.env("ENTRA_CLIENT_SECRET"),
            "scope": "https://api.securitycenter.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
        r = httpx.post(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", data=data, timeout=20)
        r.raise_for_status()
        return r.json()["access_token"]

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token_provider()}", "Content-Type": "application/json"}

    def execute(self, action: Action, dry_run: bool = True) -> ActionResult:
        if action.verb != Verb.ISOLATE_HOST or action.target.type != EntityType.HOST:
            return self._unsupported(action, dry_run)
        machine_id = quote(action.target.id, safe="")
        url = f"{API}/machines/{machine_id}/isolate"
        body = {"Comment": f"72md {action.tier}: {action.reason}"[:200], "IsolationType": self.isolation_type}
        if dry_run:
            return self._result(action, True, "POST", url, body)
        try:
            headers = self._headers()
        except (RuntimeError, httpx.HTTPError, KeyError, ValueError) as e:
            return self._result(action, False, "POST", url, body, ok=False, detail=str(e))
        return self._send(action, "POST", url, headers, body, ok_codes=(200, 201))

    def revert(self, action: Action, dry_run: bool = True) -> ActionResult:
        if action.verb != Verb.ISOLATE_HOST or action.target.type != EntityType.HOST:
            return self._unsupported(action, dry_run)
        machine_id = quote(action.target.id, safe="")
        url = f"{API}/machines/{machine_id}/unisolate"
        body = {"Comment": "72md IR lead recovery action"}
        if dry_run:
            return self._result(action, True, "POST", url, body, detail=f"DRY-RUN revert would POST {url}")
        try:
            headers = self._headers()
        except (RuntimeError, httpx.HTTPError, KeyError, ValueError) as e:
            return self._result(action, False, "POST", url, body, ok=False, detail=str(e))
        return self._send(action, "POST", url, headers, body, ok_codes=(200, 201))
