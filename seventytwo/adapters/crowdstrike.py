"""CrowdStrike Falcon adapter (official Hosts API, network containment).

Env: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_BASE_URL (default https://api.crowdstrike.com)
API scope: Hosts: Write.

Endpoints:
  POST /oauth2/token
  POST /devices/entities/devices-actions/v2?action_name=contain            {"ids": [aid]}
  POST /devices/entities/devices-actions/v2?action_name=lift_containment   {"ids": [aid]}

Tested against mocks only unless a contributor with a Falcon tenant validates it (see docs/adapters.md).
"""

from __future__ import annotations

from typing import ClassVar

import httpx

from ..models import Action, ActionResult, EntityType, Verb
from .base import Adapter


class CrowdStrikeAdapter(Adapter):
    name = "crowdstrike"
    platform_aliases = ("falcon",)
    supported: ClassVar[set[Verb]] = {Verb.ISOLATE_HOST}

    def __init__(self, token_provider=None):
        self._token_provider = token_provider or self._token

    def _base(self) -> str:
        value = self.env("FALCON_BASE_URL", required=False) or "https://api.crowdstrike.com"
        return self.https_base(value, "FALCON_BASE_URL")

    def _token(self) -> str:
        r = httpx.post(
            f"{self._base()}/oauth2/token",
            data={
                "client_id": self.env("FALCON_CLIENT_ID"),
                "client_secret": self.env("FALCON_CLIENT_SECRET"),
            },
            timeout=20,
        )
        r.raise_for_status()
        return r.json()["access_token"]

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token_provider()}", "Content-Type": "application/json"}

    def execute(self, action: Action, dry_run: bool = True) -> ActionResult:
        if action.verb != Verb.ISOLATE_HOST or action.target.type != EntityType.HOST:
            return self._unsupported(action, dry_run)
        url = f"{self._base()}/devices/entities/devices-actions/v2?action_name=contain"
        body = {"ids": [action.target.id]}
        if dry_run:
            return self._result(action, True, "POST", url, body)
        try:
            headers = self._headers()
        except (RuntimeError, httpx.HTTPError, KeyError, ValueError) as e:
            return self._result(action, False, "POST", url, body, ok=False, detail=str(e))
        return self._send(action, "POST", url, headers, body, ok_codes=(200, 202))

    def revert(self, action: Action, dry_run: bool = True) -> ActionResult:
        if action.verb != Verb.ISOLATE_HOST or action.target.type != EntityType.HOST:
            return self._unsupported(action, dry_run)
        url = f"{self._base()}/devices/entities/devices-actions/v2?action_name=lift_containment"
        body = {"ids": [action.target.id]}
        if dry_run:
            return self._result(action, True, "POST", url, body, detail=f"DRY-RUN revert would POST {url}")
        try:
            headers = self._headers()
        except (RuntimeError, httpx.HTTPError, KeyError, ValueError) as e:
            return self._result(action, False, "POST", url, body, ok=False, detail=str(e))
        return self._send(action, "POST", url, headers, body, ok_codes=(200, 202))
