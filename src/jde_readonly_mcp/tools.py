"""Read-only JD Edwards EnterpriseOne tool implementations (transport-agnostic)."""

from __future__ import annotations

import time
from typing import Any

from jde_readonly_mcp.audit import AuditLogger
from jde_readonly_mcp.config import ServerConfig
from jde_readonly_mcp.guard import (
    QueryValidationError,
    validate_identifier,
    validate_schema,
    validate_sql,
)
from jde_readonly_mcp.oracle_client import DatabaseClient, QueryResult
from jde_readonly_mcp.redact import redact_secrets


def _format_cell(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    return text.replace("\t", " ").replace("\r\n", " ").replace("\n", " ")


def _format_tsv(result: QueryResult, limit: int) -> str:
    lines: list[str] = []
    if result.columns:
        lines.append("\t".join(result.columns))
    for row in result.rows:
        lines.append("\t".join(_format_cell(cell) for cell in row))
    footer = f"Rows returned: {len(result.rows)}"
    if result.truncated:
        footer += f" (truncated at limit={limit})"
    lines.append("")
    lines.append(footer)
    return "\n".join(lines)


class JdeReadOnlyTools:
    """Core read-only tools for inspecting JD Edwards Oracle schemas and metadata."""

    def __init__(
        self,
        config: ServerConfig,
        db: DatabaseClient,
        audit: AuditLogger,
    ) -> None:
        self._config = config
        self._db = db
        self._audit = audit

    def _resolve_limit(self, limit: int | None) -> int:
        effective = self._config.default_rows if limit is None else limit
        if not isinstance(effective, int) or effective <= 0 or effective > self._config.max_rows:
            raise QueryValidationError(
                f"limit must be between 1 and {self._config.max_rows}, got {effective!r}"
            )
        return effective

    def _resolve_schema(self, schema: str | None) -> str:
        target = schema or self._config.default_schema
        if not target:
            raise QueryValidationError(
                "schema is required when JDE_DEFAULT_SCHEMA is not configured"
            )
        return validate_schema(target, self._config.allowed_schemas)

    def query(self, sql: str, limit: int | None = None) -> str:
        """Execute a validated single-statement SELECT/WITH query and return TSV."""
        start = time.perf_counter()
        try:
            effective_limit = self._resolve_limit(limit)
            cleaned_sql = validate_sql(sql)
        except QueryValidationError as exc:
            self._audit.record(
                tool="query",
                status="rejected",
                duration_ms=(time.perf_counter() - start) * 1000,
                sql=sql,
                params={"limit": limit},
                error=str(exc),
            )
            raise

        try:
            result = self._db.execute_query(cleaned_sql, max_rows=effective_limit)
        except Exception as exc:
            self._audit.record(
                tool="query",
                status="error",
                duration_ms=(time.perf_counter() - start) * 1000,
                sql=cleaned_sql,
                params={"limit": effective_limit},
                error=str(exc),
            )
            raise

        self._audit.record(
            tool="query",
            status="ok",
            duration_ms=(time.perf_counter() - start) * 1000,
            row_count=len(result.rows),
            sql=cleaned_sql,
            params={"limit": effective_limit, "truncated": result.truncated},
        )
        return _format_tsv(result, effective_limit)

    def describe_table(self, table_name: str, schema: str | None = None) -> str:
        """Inspect columns, types, nullability, and comments for an Oracle table or view."""
        start = time.perf_counter()
        try:
            owner = self._resolve_schema(schema)
            table = validate_identifier(table_name)
        except QueryValidationError as exc:
            self._audit.record(
                tool="describe_table",
                status="rejected",
                duration_ms=(time.perf_counter() - start) * 1000,
                params={"schema": schema, "table_name": table_name},
                error=str(exc),
            )
            raise

        sql = (
            "SELECT c.COLUMN_NAME, c.DATA_TYPE, c.DATA_LENGTH, c.NULLABLE, cc.COMMENTS "
            "FROM ALL_TAB_COLUMNS c "
            "LEFT JOIN ALL_COL_COMMENTS cc "
            "  ON cc.OWNER = c.OWNER "
            " AND cc.TABLE_NAME = c.TABLE_NAME "
            " AND cc.COLUMN_NAME = c.COLUMN_NAME "
            "WHERE c.OWNER = :owner AND c.TABLE_NAME = :table_name "
            "ORDER BY c.COLUMN_ID"
        )
        result = self._db.execute_query(
            sql,
            {"owner": owner, "table_name": table},
            max_rows=self._config.max_rows,
        )
        self._audit.record(
            tool="describe_table",
            status="ok",
            duration_ms=(time.perf_counter() - start) * 1000,
            row_count=len(result.rows),
            params={"owner": owner, "table_name": table},
        )

        if not result.rows:
            return f"Table or view not found (or not visible): {owner}.{table}"

        lines = [f"# {owner}.{table}", "COLUMN_NAME\tTYPE\tNULLABLE\tCOMMENTS"]
        for col_name, data_type, data_length, nullable, comments in result.rows:
            type_str = f"{data_type}({data_length})" if data_length is not None else str(data_type)
            null_str = "NULL" if str(nullable).upper() == "Y" else "NOT NULL"
            lines.append(f"{col_name}\t{type_str}\t{null_str}\t{_format_cell(comments)}")
        lines.append("")
        lines.append(f"Columns: {len(result.rows)}")
        return "\n".join(lines)

    def list_tables(
        self,
        pattern: str = "%",
        schema: str | None = None,
        limit: int = 100,
    ) -> str:
        """List accessible Oracle tables in a schema matching an optional LIKE pattern."""
        start = time.perf_counter()
        try:
            owner = self._resolve_schema(schema)
            effective_limit = self._resolve_limit(limit)
            cleaned_pattern = pattern.strip().upper() if pattern else "%"
        except QueryValidationError as exc:
            self._audit.record(
                tool="list_tables",
                status="rejected",
                duration_ms=(time.perf_counter() - start) * 1000,
                params={"schema": schema, "pattern": pattern, "limit": limit},
                error=str(exc),
            )
            raise

        sql = (
            "SELECT OWNER, TABLE_NAME, NUM_ROWS "
            "FROM ALL_TABLES "
            "WHERE OWNER = :owner AND TABLE_NAME LIKE :pattern "
            "ORDER BY TABLE_NAME"
        )
        result = self._db.execute_query(
            sql,
            {"owner": owner, "pattern": cleaned_pattern},
            max_rows=effective_limit,
        )
        self._audit.record(
            tool="list_tables",
            status="ok",
            duration_ms=(time.perf_counter() - start) * 1000,
            row_count=len(result.rows),
            params={"owner": owner, "pattern": cleaned_pattern, "limit": effective_limit},
        )
        return _format_tsv(result, effective_limit)

    def get_udo_xml(
        self,
        object_name: str,
        object_type: str | None = None,
        schema: str | None = None,
    ) -> str:
        """Fetch a JD Edwards UDO XML definition (e.g., orchestration) with secrets redacted."""
        start = time.perf_counter()
        try:
            owner = self._resolve_schema(schema)
            obj_name = validate_identifier(object_name)
            obj_type = validate_identifier(object_type) if object_type else None
        except QueryValidationError as exc:
            self._audit.record(
                tool="get_udo_xml",
                status="rejected",
                duration_ms=(time.perf_counter() - start) * 1000,
                params={"schema": schema, "object_name": object_name, "object_type": object_type},
                error=str(exc),
            )
            raise

        # Table name and schema are validated identifiers (not user-supplied SQL).
        udo_table = self._config.udo_table
        binds: dict[str, Any] = {"object_name": obj_name}
        type_filter = ""
        if obj_type:
            type_filter = " AND OMOBTYP = :object_type"
            binds["object_type"] = obj_type

        sql = (
            f"SELECT OMOBNM, OMOBTYP, UDO_XML "
            f"FROM {owner}.{udo_table} "
            f"WHERE OMOBNM = :object_name{type_filter}"
        )
        result = self._db.execute_query(sql, binds, max_rows=5)
        self._audit.record(
            tool="get_udo_xml",
            status="ok",
            duration_ms=(time.perf_counter() - start) * 1000,
            row_count=len(result.rows),
            params={"owner": owner, "object_name": obj_name, "object_type": obj_type},
        )

        if not result.rows:
            return f"UDO object not found: {owner}.{obj_name}"

        blocks: list[str] = []
        for name, otype, xml_raw in result.rows:
            redacted = redact_secrets("" if xml_raw is None else str(xml_raw))
            blocks.append(f"<!-- UDO: {name} ({otype}) -->\n{redacted}")
        return "\n\n".join(blocks)
