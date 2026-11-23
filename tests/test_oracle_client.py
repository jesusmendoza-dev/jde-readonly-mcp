import unittest
from typing import Any

from jde_readonly_mcp.config import ServerConfig
from jde_readonly_mcp.oracle_client import OracleReadOnlyClient


class FakeCursor:
    def __init__(self, rows: list[tuple[Any, ...]], description: list[tuple[Any, ...]], fail_on_query: bool = False) -> None:
        self._rows = rows
        self.description = description
        self._fail_on_query = fail_on_query
        self.executed: list[tuple[str, dict[str, Any] | None]] = []
        self.closed = False

    def execute(self, sql: str, binds: dict[str, Any] | None = None) -> None:
        self.executed.append((sql, binds))
        if self._fail_on_query and sql != "SET TRANSACTION READ ONLY":
            raise RuntimeError("ORA-00942: table or view does not exist")

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        return self._rows[:size]

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self._cursor = cursor
        self.call_timeout: int | None = None
        self.module: str | None = None
        self.action: str | None = None
        self.client_identifier: str | None = None
        self.rollback_calls = 0
        self.closed = False

    def cursor(self) -> FakeCursor:
        return self._cursor

    def rollback(self) -> None:
        self.rollback_calls += 1

    def close(self) -> None:
        self.closed = True


class TestOracleReadOnlyClient(unittest.TestCase):
    def _config(self) -> ServerConfig:
        return ServerConfig(
            dsn="db.example.internal:1521/JDEPDB",
            user="JDE_RO",
            password="secret",
            query_timeout_sec=45,
            client_tag="jde-readonly-mcp",
        )

    def test_sets_readonly_transaction_tags_session_truncates_and_rolls_back(self) -> None:
        cursor = FakeCursor(
            rows=[(1, "A"), (2, "B"), (3, "C")],
            description=[("ID",), ("NAME",)],
        )
        conn = FakeConnection(cursor)
        client = OracleReadOnlyClient(self._config(), connect_fn=lambda **_: conn)

        result = client.execute_query("SELECT ID, NAME FROM DUAL", max_rows=2)

        self.assertEqual(conn.call_timeout, 45_000)
        self.assertEqual(conn.module, "jde-readonly-mcp")
        self.assertEqual(conn.action, "readonly-query")
        self.assertEqual(conn.client_identifier, "jde-readonly-mcp")
        self.assertEqual(cursor.executed[0][0], "SET TRANSACTION READ ONLY")
        self.assertEqual(cursor.executed[1][0], "SELECT ID, NAME FROM DUAL")
        self.assertEqual(result.columns, ["ID", "NAME"])
        self.assertEqual(result.rows, [(1, "A"), (2, "B")])
        self.assertTrue(result.truncated)
        self.assertEqual(conn.rollback_calls, 1)
        self.assertTrue(cursor.closed)
        self.assertTrue(conn.closed)

    def test_rolls_back_and_closes_even_when_query_raises(self) -> None:
        cursor = FakeCursor(rows=[], description=[], fail_on_query=True)
        conn = FakeConnection(cursor)
        client = OracleReadOnlyClient(self._config(), connect_fn=lambda **_: conn)

        with self.assertRaises(RuntimeError):
            client.execute_query("SELECT * FROM NONEXISTENT", max_rows=10)

        self.assertEqual(conn.rollback_calls, 1)
        self.assertTrue(cursor.closed)
        self.assertTrue(conn.closed)


if __name__ == "__main__":
    unittest.main()
