"""MCP stdio server entrypoint for jde-readonly-mcp."""

from __future__ import annotations

from typing import Any

from jde_readonly_mcp.audit import AuditLogger
from jde_readonly_mcp.config import ServerConfig
from jde_readonly_mcp.oracle_client import OracleReadOnlyClient
from jde_readonly_mcp.tools import JdeReadOnlyTools


def build_server(config: ServerConfig | None = None) -> Any:
    """Create and configure the FastMCP server with read-only JDE tools."""
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "The official 'mcp' SDK is required to run the server. "
            "Install with: pip install mcp"
        ) from exc

    cfg = config or ServerConfig.from_env()
    db = OracleReadOnlyClient(cfg)
    audit = AuditLogger(cfg.audit_log_path)
    toolbox = JdeReadOnlyTools(cfg, db, audit)

    mcp = FastMCP("jde-readonly-mcp")

    @mcp.tool()
    def query(sql: str, limit: int | None = None) -> str:
        """Run a read-only SELECT or WITH query against JD Edwards Oracle and return TSV."""
        return toolbox.query(sql=sql, limit=limit)

    @mcp.tool()
    def describe_table(table_name: str, schema: str | None = None) -> str:
        """Inspect columns, data types, nullability, and comments for a table or view."""
        return toolbox.describe_table(table_name=table_name, schema=schema)

    @mcp.tool()
    def list_tables(
        pattern: str = "%",
        schema: str | None = None,
        limit: int = 100,
    ) -> str:
        """List accessible Oracle tables in a schema matching an optional LIKE pattern."""
        return toolbox.list_tables(pattern=pattern, schema=schema, limit=limit)

    @mcp.tool()
    def get_udo_xml(
        object_name: str,
        object_type: str | None = None,
        schema: str | None = None,
    ) -> str:
        """Fetch a JD Edwards UDO XML definition with secret values redacted."""
        return toolbox.get_udo_xml(
            object_name=object_name,
            object_type=object_type,
            schema=schema,
        )

    return mcp


def main() -> None:
    """Run jde-readonly-mcp over stdio transport."""
    server = build_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
