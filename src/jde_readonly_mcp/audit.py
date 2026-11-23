"""Structured JSONL audit logger (metadata only, never query results)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jde_readonly_mcp.redact import redact_params


class AuditLogger:
    """Append-only JSONL audit trail for tool invocations.

    Records tool name, status, SQL text, row count, and duration.
    Never logs result rows or credentials.
    """

    def __init__(self, path: Path | None) -> None:
        self._path = path

    @property
    def path(self) -> Path | None:
        return self._path

    def record(
        self,
        *,
        tool: str,
        status: str,
        duration_ms: float,
        row_count: int = 0,
        sql: str | None = None,
        params: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        if self._path is None:
            return

        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "status": status,
            "row_count": row_count,
            "duration_ms": round(duration_ms, 2),
        }
        if sql is not None:
            entry["sql"] = sql
        if params:
            entry["params"] = redact_params(params)
        if error is not None:
            entry["error"] = error

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
