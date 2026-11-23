"""Configuration loading for jde-readonly-mcp."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from jde_readonly_mcp.guard import QueryValidationError, validate_identifier


class ConfigError(ValueError):
    """Raised when required server configuration is missing or invalid."""


KeyringGetter = Callable[[str, str], str | None]


def _default_keyring_getter(service: str, user: str) -> str | None:
    try:
        import keyring  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ConfigError(
            "JDE_KEYRING_SERVICE is set, but the optional 'keyring' package is not installed. "
            "Install with: pip install 'jde-readonly-mcp[keyring]'"
        ) from exc
    return keyring.get_password(service, user)


def _parse_positive_int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a positive integer, got {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{key} must be > 0, got {value}")
    return value


@dataclass(frozen=True)
class ServerConfig:
    """Immutable runtime configuration for the read-only JDE Oracle MCP server."""

    dsn: str
    user: str
    password: str
    default_schema: str | None = None
    allowed_schemas: frozenset[str] = frozenset()
    default_rows: int = 200
    max_rows: int = 2000
    query_timeout_sec: int = 120
    client_tag: str = "jde-readonly-mcp"
    audit_log_path: Path | None = None
    udo_table: str = "F98220"

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        keyring_getter: KeyringGetter | None = None,
    ) -> ServerConfig:
        source = os.environ if env is None else env

        dsn = source.get("JDE_DB_DSN", "").strip()
        user = source.get("JDE_DB_USER", "").strip()
        if not dsn:
            raise ConfigError("JDE_DB_DSN is required")
        if not user:
            raise ConfigError("JDE_DB_USER is required")

        password = source.get("JDE_DB_PASSWORD", "")
        keyring_service = source.get("JDE_KEYRING_SERVICE", "").strip()
        if not password and keyring_service:
            getter = keyring_getter or _default_keyring_getter
            resolved = getter(keyring_service, user)
            if not resolved:
                raise ConfigError(
                    f"No password found in keyring for service={keyring_service!r}, user={user!r}"
                )
            password = resolved
        if not password:
            raise ConfigError("Either JDE_DB_PASSWORD or JDE_KEYRING_SERVICE is required")

        raw_allowed = source.get("JDE_ALLOWED_SCHEMAS", "").strip()
        allowed_list: list[str] = []
        if raw_allowed:
            for item in raw_allowed.split(","):
                cleaned = item.strip()
                if not cleaned:
                    continue
                try:
                    allowed_list.append(validate_identifier(cleaned))
                except QueryValidationError as exc:
                    raise ConfigError(f"Invalid schema in JDE_ALLOWED_SCHEMAS: {cleaned!r}") from exc
        allowed_schemas = frozenset(allowed_list)

        raw_default_schema = source.get("JDE_DEFAULT_SCHEMA", "").strip()
        default_schema: str | None = None
        if raw_default_schema:
            try:
                default_schema = validate_identifier(raw_default_schema)
            except QueryValidationError as exc:
                raise ConfigError(f"Invalid JDE_DEFAULT_SCHEMA: {raw_default_schema!r}") from exc
            if allowed_schemas and default_schema not in allowed_schemas:
                raise ConfigError(
                    f"JDE_DEFAULT_SCHEMA ({default_schema}) is not in JDE_ALLOWED_SCHEMAS"
                )

        default_rows = _parse_positive_int(source, "JDE_DEFAULT_ROWS", 200)
        max_rows = _parse_positive_int(source, "JDE_MAX_ROWS", 2000)
        if default_rows > max_rows:
            raise ConfigError(
                f"JDE_DEFAULT_ROWS ({default_rows}) cannot exceed JDE_MAX_ROWS ({max_rows})"
            )

        query_timeout_sec = _parse_positive_int(source, "JDE_QUERY_TIMEOUT_SEC", 120)
        client_tag = source.get("JDE_CLIENT_TAG", "").strip() or "jde-readonly-mcp"

        raw_audit = source.get("JDE_AUDIT_LOG_PATH", "").strip()
        audit_log_path = Path(raw_audit) if raw_audit else None

        raw_udo_table = source.get("JDE_UDO_TABLE", "").strip() or "F98220"
        try:
            udo_table = validate_identifier(raw_udo_table)
        except QueryValidationError as exc:
            raise ConfigError(f"Invalid JDE_UDO_TABLE: {raw_udo_table!r}") from exc

        return cls(
            dsn=dsn,
            user=user,
            password=password,
            default_schema=default_schema,
            allowed_schemas=allowed_schemas,
            default_rows=default_rows,
            max_rows=max_rows,
            query_timeout_sec=query_timeout_sec,
            client_tag=client_tag,
            audit_log_path=audit_log_path,
            udo_table=udo_table,
        )
