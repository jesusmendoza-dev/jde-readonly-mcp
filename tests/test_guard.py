import unittest

from jde_readonly_mcp.guard import (
    QueryValidationError,
    validate_identifier,
    validate_schema,
    validate_sql,
)


class TestValidateSql(unittest.TestCase):
    def test_accepts_basic_select(self) -> None:
        cleaned = validate_sql("SELECT AN8, ALPH FROM PRODDTA.F0101 WHERE AT1 = 'C'")
        self.assertEqual(cleaned, "SELECT AN8, ALPH FROM PRODDTA.F0101 WHERE AT1 = 'C'")

    def test_accepts_select_with_single_trailing_semicolon(self) -> None:
        cleaned = validate_sql("  SELECT 1 FROM DUAL;  ")
        self.assertEqual(cleaned, "SELECT 1 FROM DUAL")

    def test_accepts_cte_with_query(self) -> None:
        sql = """
        WITH active_orders AS (
            SELECT SDDOCO, SDDCTO FROM PRODDTA.F4211 WHERE SDLNTY = 'S'
        )
        SELECT COUNT(*) FROM active_orders
        """
        cleaned = validate_sql(sql)
        self.assertTrue(cleaned.startswith("WITH active_orders"))

    def test_allows_blocked_words_inside_string_literals_and_comments(self) -> None:
        sql = """
        -- Explain why DELETE or DROP is mentioned in a comment
        SELECT 'DELETE FROM F0101; DROP TABLE X' AS note,
               'FOR UPDATE' AS lock_text
        FROM DUAL /* UPDATE comment */
        """
        cleaned = validate_sql(sql)
        self.assertIn("SELECT", cleaned)

    def test_allows_column_names_containing_keyword_substrings(self) -> None:
        sql = "SELECT UPDATED_AT, CREATED_BY, DELETED_FLAG, EXECUTION_ID FROM PRODDTA.F0101"
        self.assertEqual(validate_sql(sql), sql)

    def test_rejects_empty_or_comment_only_sql(self) -> None:
        for bad in ("", "   ", "-- just a comment", "/* block comment */"):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryValidationError):
                    validate_sql(bad)

    def test_rejects_multiple_statements(self) -> None:
        for bad in (
            "SELECT 1 FROM DUAL; SELECT 2 FROM DUAL",
            "SELECT 1 FROM DUAL; DROP TABLE PRODDTA.F0101",
            "SELECT 1 FROM DUAL;;",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryValidationError):
                    validate_sql(bad)

    def test_rejects_non_select_or_with_statements(self) -> None:
        for bad in (
            "INSERT INTO PRODDTA.F0101 (AN8) VALUES (1)",
            "UPDATE PRODDTA.F0101 SET ALPH = 'X'",
            "DELETE FROM PRODDTA.F0101",
            "MERGE INTO PRODDTA.F0101 USING DUAL ON (1=1) WHEN MATCHED THEN UPDATE SET ALPH='X'",
            "DROP TABLE PRODDTA.F0101",
            "ALTER SYSTEM FLUSH BUFFER_CACHE",
            "CREATE TABLE T1 (ID NUMBER)",
            "TRUNCATE TABLE PRODDTA.F0101",
            "GRANT SELECT ON PRODDTA.F0101 TO PUBLIC",
            "REVOKE SELECT ON PRODDTA.F0101 FROM PUBLIC",
            "BEGIN NULL; END;",
            "DECLARE x NUMBER; BEGIN x := 1; END;",
            "CALL some_proc()",
            "EXECUTE IMMEDIATE 'DROP TABLE T1'",
            "SET ROLE ALL",
            "COMMIT",
            "ROLLBACK",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryValidationError):
                    validate_sql(bad)

    def test_rejects_for_update_locking(self) -> None:
        for bad in (
            "SELECT * FROM PRODDTA.F0101 FOR UPDATE",
            "SELECT * FROM PRODDTA.F0101 FOR   UPDATE NOWAIT",
            "SELECT * FROM PRODDTA.F0101 FOR/*comment*/UPDATE",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryValidationError):
                    validate_sql(bad)

    def test_rejects_inline_plsql_with_function_or_procedure(self) -> None:
        for bad in (
            "WITH FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END; SELECT f FROM DUAL",
            "WITH PROCEDURE p IS BEGIN NULL; END; SELECT 1 FROM DUAL",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryValidationError):
                    validate_sql(bad)

    def test_rejects_dangerous_oracle_packages(self) -> None:
        for bad in (
            "SELECT DBMS_XMLGEN.GETXML('SELECT 1 FROM DUAL') FROM DUAL",
            "SELECT SYS.DBMS_SQL.OPEN_CURSOR FROM DUAL",
            "SELECT UTL_HTTP.REQUEST('http://169.254.169.254/') FROM DUAL",
            "SELECT UTL_INADDR.GET_HOST_ADDRESS('example.com') FROM DUAL",
            "SELECT HTTPURITYPE('http://example.com').GETCLOB() FROM DUAL",
            "SELECT OWA_UTIL.GET_CGI_ENV('PATH') FROM DUAL",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryValidationError):
                    validate_sql(bad)

    def test_rejects_unterminated_string_or_comment(self) -> None:
        for bad in (
            "SELECT 'unterminated FROM DUAL",
            "SELECT /* unterminated FROM DUAL",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryValidationError):
                    validate_sql(bad)


class TestIdentifiersAndSchemas(unittest.TestCase):
    def test_validate_identifier_normalizes_uppercase(self) -> None:
        self.assertEqual(validate_identifier("f0101"), "F0101")
        self.assertEqual(validate_identifier("F4211_HIST$1"), "F4211_HIST$1")

    def test_validate_identifier_rejects_injection_chars(self) -> None:
        for bad in ("", "123ABC", "F0101; DROP TABLE X", "PRODDTA.F0101", "F0101' OR '1'='1"):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryValidationError):
                    validate_identifier(bad)

    def test_validate_schema_enforces_allowlist(self) -> None:
        allowed = frozenset({"PRODDTA", "PRODCTL"})
        self.assertEqual(validate_schema("proddta", allowed), "PRODDTA")
        with self.assertRaises(QueryValidationError):
            validate_schema("SYS", allowed)

    def test_validate_schema_allows_any_valid_identifier_when_allowlist_empty(self) -> None:
        self.assertEqual(validate_schema("sy920", frozenset()), "SY920")


if __name__ == "__main__":
    unittest.main()
