"""Append-only, hash-chained audit log.

Every decision and every action (dry-run or live) is a record whose hash includes the previous
record's hash. In-place edits, reordering, and deletion from the middle break the chain, which
`72md audit verify` reports. A local hash chain cannot prove that the tail was not truncated or
the entire file rewritten; production deployments must stream records or signed checkpoints to
independently controlled immutable storage.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        with open(self.path, "rb") as f:
            last = None
            for line in f:
                if line.strip():
                    last = line
        return json.loads(last)["hash"] if last else GENESIS

    @staticmethod
    def _hash(prev: str, body: dict[str, Any]) -> str:
        payload = prev + json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def append(self, kind: str, actor: str, **fields: Any) -> dict[str, Any]:
        prev = self._last_hash()
        body = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "kind": kind,
            "actor": actor,
            **fields,
        }
        rec = {**body, "prev": prev, "hash": self._hash(prev, body)}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        return rec

    def verify(self) -> tuple[bool, int, str]:
        """Returns (ok, records_checked, message)."""
        if not self.path.exists():
            return True, 0, "no audit log yet"
        prev = GENESIS
        n = 0
        with open(self.path, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    return False, n, f"line {i}: invalid JSON ({exc.msg})"
                body = {k: v for k, v in rec.items() if k not in ("prev", "hash")}
                if rec.get("prev") != prev:
                    return False, n, f"line {i}: prev-hash mismatch (record deleted or reordered before here)"
                if self._hash(prev, body) != rec.get("hash"):
                    return False, n, f"line {i}: content hash mismatch (record modified)"
                prev = rec["hash"]
                n += 1
        return True, n, f"{n} records, chain intact"

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
