import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from jde_readonly_mcp.audit import AuditLogger
from jde_readonly_mcp.config import ServerConfig
from jde_readonly_mcp.guard import QueryValidationError
from jde_readonly_mcp.oracle_client import QueryResult
from jde_readonly_mcp.tools import JdeReadOnlyTools


class FakeDatabaseClient:
    def __init__(self, responses: list[QueryResult] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[dict[str, Any]] = []

    def execute_query(
        self,
        sql: str,
        binds: dict[str, Any] | None = None,
        *,
        max_rows: int = 200,
    ) -> QueryResult:
        self.calls.append({"sql": sql, "binds": binds or {}, "max_rows": max_rows})
        if not self.responses:
            return QueryResult(columns=[], rows=[], truncated=False)
        return self.responses.pop(0)


def _make_config(audit_path: Path | None = None) -> ServerConfig:
    return ServerConfig(
        dsn="db.example.internal:1521/JDEPDB",
        user="JDE_RO",
        password="secret",
        default_schema="PRODDTA",
        allowed_schemas=frozenset({"PRODDTA", "PRODCTL", "SY920"}),
        default_rows=200,
        max_rows=500,
        query_timeout_sec=60,
        audit_log_path=audit_path,
    )


class TestJdeReadOnlyTools(unittest.TestCase):
    def test_query_returns_tsv_and_audits_without_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "audit.jsonl"
            fake_db = FakeDatabaseClient(
                [
                    QueryResult(
                        columns=["AN8", "ALPH"],
                        rows=[(1001, "ACME CORP"), (1002, "BETA LLC")],
                        truncated=False,
                    )
                ]
            )
            tools = JdeReadOnlyTools(_make_config(audit_path), fake_db, AuditLogger(audit_path))
            output = tools.query("SELECT AN8, ALPH FROM PRODDTA.F0101", limit=50)

            self.assertIn("AN8\tALPH", output)
            self.assertIn("1001\tACME CORP", output)
            self.assertIn("Rows returned: 2", output)
            self.assertEqual(fake_db.calls[0]["max_rows"], 50)

            entry = json.loads(audit_path.read_text(encoding="utf-8").strip())
            self.assertEqual(entry["status"], "ok")
            self.assertEqual(entry["row_count"], 2)
            self.assertNotIn("ACME CORP", json.dumps(entry))

    def test_query_marks_truncated_results(self) -> None:
        fake_db = FakeDatabaseClient(
            [QueryResult(columns=["AN8"], rows=[(1,), (2,)], truncated=True)]
        )
        tools = JdeReadOnlyTools(_make_config(), fake_db, AuditLogger(None))
        output = tools.query("SELECT AN8 FROM PRODDTA.F0101", limit=2)
        self.assertIn("truncated at limit=2", output)

    def test_query_rejects_write_sql_before_hitting_db_and_audits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "audit.jsonl"
            fake_db = FakeDatabaseClient()
            tools = JdeReadOnlyTools(_make_config(audit_path), fake_db, AuditLogger(audit_path))

            with self.assertRaises(QueryValidationError):
                tools.query("DELETE FROM PRODDTA.F0101")

            self.assertEqual(fake_db.calls, [])
            entry = json.loads(audit_path.read_text(encoding="utf-8").strip())
            self.assertEqual(entry["status"], "rejected")

    def test_query_rejects_limit_out_of_bounds(self) -> None:
        fake_db = FakeDatabaseClient()
        tools = JdeReadOnlyTools(_make_config(), fake_db, AuditLogger(None))
        with self.assertRaises(QueryValidationError):
            tools.query("SELECT 1 FROM DUAL", limit=0)
        with self.assertRaises(QueryValidationError):
            tools.query("SELECT 1 FROM DUAL", limit=501)
        self.assertEqual(fake_db.calls, [])

    def test_describe_table_uses_bind_variables_and_enforces_schema_allowlist(self) -> None:
        fake_db = FakeDatabaseClient(
            [
                QueryResult(
                    columns=["COLUMN_NAME", "DATA_TYPE", "DATA_LENGTH", "NULLABLE", "COMMENTS"],
                    rows=[
                        ("ABAN8", "NUMBER", 22, "N", "Address Number"),
                        ("ABALPH", "NCHAR", 80, "Y", "Alpha Name"),
                    ],
                    truncated=False,
                )
            ]
        )
        tools = JdeReadOnlyTools(_make_config(), fake_db, AuditLogger(None))
        output = tools.describe_table("f0101")

        self.assertIn("PRODDTA.F0101", output)
        self.assertIn("ABAN8\tNUMBER(22)\tNOT NULL\tAddress Number", output)
        self.assertEqual(
            fake_db.calls[0]["binds"],
            {"owner": "PRODDTA", "table_name": "F0101"},
        )

        with self.assertRaises(QueryValidationError):
            tools.describe_table("F0101", schema="SYS")

    def test_list_tables_uses_bind_variables(self) -> None:
        fake_db = FakeDatabaseClient(
            [
                QueryResult(
                    columns=["OWNER", "TABLE_NAME", "NUM_ROWS"],
                    rows=[("PRODDTA", "F0101", 12500), ("PRODDTA", "F0116", 12490)],
                    truncated=False,
                )
            ]
        )
        tools = JdeReadOnlyTools(_make_config(), fake_db, AuditLogger(None))
        output = tools.list_tables(pattern="F01%", schema="PRODDTA", limit=50)

        self.assertIn("PRODDTA\tF0101\t12500", output)
        self.assertEqual(
            fake_db.calls[0]["binds"],
            {"owner": "PRODDTA", "pattern": "F01%"},
        )

    def test_get_udo_xml_redacts_secrets(self) -> None:
        xml_payload = (
            "<Orchestration name='ORCH_DEMO'>"
            "<Password>TopSecret999</Password>"
            "<Endpoint>https://api.example.internal/v1</Endpoint>"
            "</Orchestration>"
        )
        fake_db = FakeDatabaseClient(
            [
                QueryResult(
                    columns=["OMOBNM", "OMOBTYP", "XML_CONTENT"],
                    rows=[("ORCH_DEMO", "ORCH", xml_payload)],
                    truncated=False,
                )
            ]
        )
        tools = JdeReadOnlyTools(_make_config(), fake_db, AuditLogger(None))
        output = tools.get_udo_xml("ORCH_DEMO", schema="PRODCTL")

        self.assertIn("https://api.example.internal/v1", output)
        self.assertNotIn("TopSecret999", output)
        self.assertIn("<Password>[REDACTED]</Password>", output)
        self.assertEqual(fake_db.calls[0]["binds"]["object_name"], "ORCH_DEMO")


if __name__ == "__main__":
    unittest.main()
