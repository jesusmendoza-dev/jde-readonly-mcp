import json
import tempfile
import unittest
from pathlib import Path

from jde_readonly_mcp.audit import AuditLogger
from jde_readonly_mcp.redact import redact_secrets


class TestRedactSecrets(unittest.TestCase):
    def test_redacts_xml_secret_tags(self) -> None:
        xml = (
            "<Connection>"
            "<Host>erp.example.internal</Host>"
            "<Password>SuperSecret123!</Password>"
            "<ApiKey>sk-live-99999</ApiKey>"
            "<ClientSecret>abc-xyz</ClientSecret>"
            "</Connection>"
        )
        redacted = redact_secrets(xml)
        self.assertIn("<Host>erp.example.internal</Host>", redacted)
        self.assertNotIn("SuperSecret123!", redacted)
        self.assertNotIn("sk-live-99999", redacted)
        self.assertNotIn("abc-xyz", redacted)
        self.assertIn("<Password>[REDACTED]</Password>", redacted)
        self.assertIn("<ApiKey>[REDACTED]</ApiKey>", redacted)

    def test_redacts_json_and_key_value_secrets(self) -> None:
        text = (
            '{"username": "svc_orch", "password": "MyPassword99", '
            '"access_token": "tok_12345", "Authorization": "Bearer eyJhbGciOi..."}\n'
            'private_key=-----BEGIN-FAKE-KEY-----'
        )
        redacted = redact_secrets(text)
        self.assertIn('"username": "svc_orch"', redacted)
        self.assertNotIn("MyPassword99", redacted)
        self.assertNotIn("tok_12345", redacted)
        self.assertNotIn("eyJhbGciOi", redacted)
        self.assertNotIn("BEGIN-FAKE-KEY", redacted)


class TestAuditLogger(unittest.TestCase):
    def test_writes_jsonl_without_result_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit" / "queries.jsonl"
            logger = AuditLogger(log_path)
            logger.record(
                tool="query",
                status="ok",
                duration_ms=42.5,
                row_count=10,
                sql="SELECT AN8 FROM PRODDTA.F0101 WHERE ALPH = 'ACME'",
                params={"limit": 200},
            )

            lines = log_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["tool"], "query")
            self.assertEqual(entry["status"], "ok")
            self.assertEqual(entry["row_count"], 10)
            self.assertEqual(entry["duration_ms"], 42.5)
            self.assertIn("timestamp", entry)
            self.assertNotIn("rows", entry)
            self.assertNotIn("result", entry)

    def test_masks_sensitive_params_in_audit_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "queries.jsonl"
            logger = AuditLogger(log_path)
            logger.record(
                tool="query",
                status="rejected",
                duration_ms=1.2,
                row_count=0,
                sql="SELECT 1 FROM DUAL; DROP TABLE X",
                params={"token": "secret-val", "schema": "PRODDTA"},
                error="Multiple statements are not allowed",
            )
            entry = json.loads(log_path.read_text(encoding="utf-8").strip())
            self.assertEqual(entry["params"]["token"], "[REDACTED]")
            self.assertEqual(entry["params"]["schema"], "PRODDTA")
            self.assertEqual(entry["error"], "Multiple statements are not allowed")


if __name__ == "__main__":
    unittest.main()
