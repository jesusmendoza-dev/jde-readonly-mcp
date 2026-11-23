# Security Model

`jde-readonly-mcp` is built for read-only inspection of JD Edwards EnterpriseOne on Oracle Database. Treat its application-level guards as a second line of defense, never as a replacement for least-privilege Oracle permissions.

## Required Database-Side Controls

Create a dedicated Oracle account with read-only grants scoped strictly to the tables and views the agent needs:

```sql
-- Example template (adapt tablespaces, profile, and grants to your DBA policy)
CREATE USER JDE_RO_AGENT IDENTIFIED BY "<strong-random-password>"
  PROFILE DEFAULT
  ACCOUNT UNLOCK;

GRANT CREATE SESSION TO JDE_RO_AGENT;

-- Prefer explicit per-table grants over SELECT ANY TABLE:
GRANT SELECT ON PRODDTA.F0101 TO JDE_RO_AGENT;
GRANT SELECT ON PRODDTA.F4211 TO JDE_RO_AGENT;
```

Recommendations:
- Never connect with `SYS`, `SYSTEM`, or an application owner account (`PRODDTA`, `PRODCTL`, `JDE`).
- Avoid `SELECT ANY TABLE` when a narrower grant set is practical.
- Enforce a resource profile (`IDLE_TIME`, `CPU_PER_CALL`, `LOGICAL_READS_PER_CALL`) so an expensive ad-hoc query cannot impact production OLTP workloads.
- Point the server at a physical standby / Data Guard read-only replica whenever available.

## What This Server Enforces

- Single-statement `SELECT` or `WITH` queries only.
- Blocks DML, DDL, DCL, transaction control, `FOR UPDATE`, Oracle inline PL/SQL (`WITH FUNCTION` / `WITH PROCEDURE`), and dangerous built-in packages (`DBMS_*`, `UTL_*`, `OWA_*`, `CTX_DDL`, `HTTPURITYPE`).
- Executes every query inside `SET TRANSACTION READ ONLY` with `call_timeout` and unconditional `ROLLBACK`.
- Validates Oracle identifiers and enforces `JDE_ALLOWED_SCHEMAS` on metadata tools.
- Redacts secret-like patterns in UDO XML responses.
- Writes metadata-only JSONL audit entries (no query result rows, no credentials).

## Known Limitations

- **Query result sensitivity**: `query` returns raw column values from whatever tables the Oracle user can read. Sensitive business data (PII, pricing, payroll) must be restricted via Oracle grants or views, not by the MCP client.
- **Regex redaction is best-effort**: `redact_secrets` masks common XML/JSON/key-value secret patterns, not arbitrary unlabelled strings.
- **External LLM data flow**: Anything returned by a tool is sent to the configured MCP client and model provider. Review your organization's data governance policy before connecting an external model to production ERP data.
