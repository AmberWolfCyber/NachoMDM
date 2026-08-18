from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import itertools
import json
import re
import threading


class TraceLogger:
    def __init__(self, *, enabled: bool, log_dir: str):
        self.enabled = enabled
        self.log_dir = Path(log_dir)
        self._counter = itertools.count(1)
        self._lock = threading.Lock()
        if self.enabled:
            self.log_dir.mkdir(parents=True, exist_ok=True)

    def event(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        if not self.enabled:
            return
        entry = {
            "ts": _timestamp(),
            "event": event_type,
            "payload": payload or {},
        }
        with self._lock:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            with (self.log_dir / "events.ndjson").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def exchange(
        self,
        label: str,
        *,
        request_body: bytes | str | None = None,
        response_body: bytes | str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Path | None:
        if not self.enabled:
            return None
        prefix = self._prefix(label)
        if meta is not None:
            _write_text(_append_suffix(prefix, ".meta.json"), json.dumps(meta, indent=2, sort_keys=True))
        if request_body is not None:
            _write_payload(_append_suffix(prefix, ".request.xml"), request_body)
        if response_body is not None:
            _write_payload(_append_suffix(prefix, ".response.xml"), response_body)
        self.event(
            "exchange",
            {
                "label": label,
                "prefix": prefix.name,
                "meta": meta or {},
                "request_logged": request_body is not None,
                "response_logged": response_body is not None,
            },
        )
        return prefix

    def artifact(
        self,
        label: str,
        body: bytes | str,
        *,
        extension: str,
        meta: dict[str, Any] | None = None,
    ) -> Path | None:
        if not self.enabled:
            return None
        prefix = self._prefix(label)
        suffix = extension if extension.startswith(".") else f".{extension}"
        if meta is not None:
            _write_text(_append_suffix(prefix, ".meta.json"), json.dumps(meta, indent=2, sort_keys=True))
        target = _append_suffix(prefix, suffix)
        _write_payload(target, body)
        self.event(
            "artifact",
            {
                "label": label,
                "prefix": prefix.name,
                "meta": meta or {},
                "path": target.name,
            },
        )
        return target

    def _prefix(self, label: str) -> Path:
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-") or "trace"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        with self._lock:
            seq = next(self._counter)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        return self.log_dir / f"{stamp}-{seq:04d}-{safe_label}"


def _write_payload(path: Path, body: bytes | str) -> None:
    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            path.write_bytes(body)
            return
    else:
        text = body
    _write_text(path, text)


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _append_suffix(path: Path, suffix: str) -> Path:
    return path.with_name(path.name + suffix)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
