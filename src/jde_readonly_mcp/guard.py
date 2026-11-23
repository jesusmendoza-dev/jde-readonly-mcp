"""SQL read-only guard and Oracle identifier validation."""

from __future__ import annotations

import re

IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_$#]{0,127}$")

ALLOWED_LEADING_KEYWORDS = frozenset({"SELECT", "WITH"})

BLOCKED_KEYWORDS = frozenset(
    {
        "INSERT",
        "UPDATE",
        "DELETE",
        "MERGE",
        "DROP",
        "ALTER",
        "CREATE",
        "TRUNCATE",
        "GRANT",
        "REVOKE",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT",
        "EXEC",
        "EXECUTE",
        "CALL",
        "BEGIN",
        "DECLARE",
        "LOCK",
        "RENAME",
        "COMMENT",
        "ANALYZE",
        "AUDIT",
        "NOAUDIT",
        "FLASHBACK",
        "PURGE",
        "SET",
        "EXPLAIN",
    }
)

FOR_UPDATE_RE = re.compile(r"\bFOR\s+UPDATE\b", re.IGNORECASE)
INLINE_PLSQL_RE = re.compile(r"\bWITH\s+(?:FUNCTION|PROCEDURE)\b", re.IGNORECASE)
DANGEROUS_PACKAGES_RE = re.compile(
    r"\b(?:SYS\.)?(?:DBMS_[A-Z0-9_$#]+|UTL_[A-Z0-9_$#]+|OWA_[A-Z0-9_$#]+|"
    r"CTX_DDL|HTTPURITYPE|URIFACTORY)\b",
    re.IGNORECASE,
)
WORD_TOKEN_RE = re.compile(r"\b[A-Z_][A-Z0-9_$#]*\b")


class QueryValidationError(ValueError):
    """Raised when a SQL statement or identifier violates read-only guard rules."""


def _strip_comments_and_strings(sql: str) -> str:
    """Remove comments and blank out string literals for structural keyword scanning."""
    out: list[str] = []
    i = 0
    n = len(sql)

    while i < n:
        ch = sql[i]

        # Line comment: -- ... \n
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            i += 2
            while i < n and sql[i] != "\n":
                i += 1
            out.append(" ")
            continue

        # Block comment: /* ... */
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            end = sql.find("*/", i + 2)
            if end == -1:
                raise QueryValidationError("Unterminated block comment in SQL")
            i = end + 2
            out.append(" ")
            continue

        # Single-quoted string literal: '...' with '' escaping
        if ch == "'":
            i += 1
            closed = False
            while i < n:
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        i += 2
                        continue
                    closed = True
                    i += 1
                    break
                i += 1
            if not closed:
                raise QueryValidationError("Unterminated string literal in SQL")
            out.append(" '' ")
            continue

        # Double-quoted identifier: "..."
        if ch == '"':
            i += 1
            closed = False
            while i < n:
                if sql[i] == '"':
                    if i + 1 < n and sql[i + 1] == '"':
                        i += 2
                        continue
                    closed = True
                    i += 1
                    break
                i += 1
            if not closed:
                raise QueryValidationError("Unterminated quoted identifier in SQL")
            out.append(' "" ')
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def validate_sql(sql: str) -> str:
    """Validate that SQL is a single read-only SELECT or WITH query.

    Returns the trimmed SQL without a trailing semicolon.
    """
    if not isinstance(sql, str) or not sql.strip():
        raise QueryValidationError("SQL query must not be empty")

    stripped_code = _strip_comments_and_strings(sql).strip()
    if not stripped_code:
        raise QueryValidationError("SQL query contains no executable tokens")

    # Allow at most a single trailing semicolon
    cleaned_return = sql.strip()
    if stripped_code.endswith(";"):
        stripped_code = stripped_code[:-1].rstrip()
        if cleaned_return.endswith(";"):
            cleaned_return = cleaned_return[:-1].rstrip()

    if ";" in stripped_code:
        raise QueryValidationError("Multiple statements are not allowed")

    upper_code = stripped_code.upper()
    first_match = WORD_TOKEN_RE.match(upper_code)
    if not first_match or first_match.group(0) not in ALLOWED_LEADING_KEYWORDS:
        raise QueryValidationError("Only read-only SELECT or WITH statements are allowed")

    if INLINE_PLSQL_RE.search(upper_code):
        raise QueryValidationError("Inline PL/SQL (WITH FUNCTION/PROCEDURE) is not allowed")

    if FOR_UPDATE_RE.search(upper_code):
        raise QueryValidationError("FOR UPDATE row locking is not allowed")

    danger_match = DANGEROUS_PACKAGES_RE.search(upper_code)
    if danger_match:
        raise QueryValidationError(
            f"Dangerous Oracle package or type is not allowed: {danger_match.group(0)}"
        )

    for token in WORD_TOKEN_RE.findall(upper_code):
        if token in BLOCKED_KEYWORDS:
            raise QueryValidationError(f"Blocked SQL keyword is not allowed: {token}")

    return cleaned_return


def validate_identifier(name: str) -> str:
    """Validate an unquoted Oracle identifier and normalize to uppercase."""
    if not isinstance(name, str):
        raise QueryValidationError("Identifier must be a string")
    cleaned = name.strip()
    if not IDENTIFIER_RE.match(cleaned):
        raise QueryValidationError(f"Invalid Oracle identifier: {name!r}")
    return cleaned.upper()


def validate_schema(schema: str, allowed_schemas: frozenset[str] = frozenset()) -> str:
    """Validate an Oracle schema name and enforce optional allow-list."""
    normalized = validate_identifier(schema)
    if allowed_schemas and normalized not in allowed_schemas:
        raise QueryValidationError(
            f"Schema {normalized!r} is not in the configured allow-list"
        )
    return normalized
