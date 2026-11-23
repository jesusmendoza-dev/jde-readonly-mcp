"""Read-only Oracle Database adapter with timeout, session tagging, and forced rollback."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from jde_readonly_mcp.config import ServerConfig


@dataclass(frozen=True)
class QueryResult:
    """Bounded result returned from a read-only database query."""

    columns: list[str]
    rows: list[tuple[Any, ...]]
    truncated: bool = False


class DatabaseClient(Protocol):
    """Minimal read-only database execution contract."""

    def execute_query(
        self,
        sql: str,
        binds: dict[str, Any] | None = None,
        *,
        max_rows: int = 200,
    ) -> QueryResult: ...


def _default_connect(**kwargs: Any) -> Any:
    try:
        import oracledb  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "python-oracledb is required to connect to Oracle. "
            "Install with: pip install oracledb"
        ) from exc
    return oracledb.connect(**kwargs)


def _materialize_value(value: Any) -> Any:
    """Convert Oracle LOB objects into strings/bytes before closing the cursor."""
    read_fn = getattr(value, "read", None)
    if callable(read_fn):
        raw = read_fn()
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return raw
    return value


class OracleReadOnlyClient:
    """Executes single queries inside an explicit READ ONLY transaction with rollback."""

    def __init__(
        self,
        config: ServerConfig,
        connect_fn: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._connect_fn = connect_fn or _default_connect

    def execute_query(
        self,
        sql: str,
        binds: dict[str, Any] | None = None,
        *,
        max_rows: int = 200,
    ) -> QueryResult:
        conn = self._connect_fn(
            user=self._config.user,
            password=self._config.password,
            dsn=self._config.dsn,
        )
        cursor = None
        try:
            conn.call_timeout = self._config.query_timeout_sec * 1000
            conn.module = self._config.client_tag
            conn.action = "readonly-query"
            conn.client_identifier = self._config.client_tag

            cursor = conn.cursor()
            cursor.execute("SET TRANSACTION READ ONLY")
            if binds:
                cursor.execute(sql, binds)
            else:
                cursor.execute(sql)

            columns = [col[0] for col in (cursor.description or [])]
            fetched = cursor.fetchmany(max_rows + 1)
            truncated = len(fetched) > max_rows
            bounded = fetched[:max_rows]
            rows = [tuple(_materialize_value(cell) for cell in row) for row in bounded]
            return QueryResult(columns=columns, rows=rows, truncated=truncated)
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    pass
            try:
                conn.rollback()
            finally:
                conn.close()
