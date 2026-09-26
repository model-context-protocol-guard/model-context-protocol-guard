"""Append-only JSONL audit log with a SHA-256 hash chain."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class AuditLog:
    path: Path
    previous_hash: str = "0" * 64

    def __post_init__(self) -> None:
        if self.path.exists():
            last = None
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    last = json.loads(line)
            if last:
                self.previous_hash = str(last["hash"])

    def append(self, event: str, data: dict[str, Any]) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp_utc": _utc_now(),
            "event": event,
            "data": data,
            "previous_hash": self.previous_hash,
        }
        payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        record["hash"] = digest
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(
                json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            )
        self.previous_hash = digest
        return digest


def verify_chain(path: Path) -> bool:
    previous = "0" * 64
    for line in path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        digest = str(record.pop("hash"))
        if record.get("previous_hash") != previous:
            return False
        payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if hashlib.sha256(payload.encode("utf-8")).hexdigest() != digest:
            return False
        previous = digest
    return True
