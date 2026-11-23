import unittest

from jde_readonly_mcp.config import ConfigError, ServerConfig


class TestServerConfig(unittest.TestCase):
    def test_loads_from_env_with_defaults(self) -> None:
        env = {
            "JDE_DB_DSN": "db.example.internal:1521/JDEPDB",
            "JDE_DB_USER": "JDE_RO",
            "JDE_DB_PASSWORD": "secret",
        }
        cfg = ServerConfig.from_env(env)
        self.assertEqual(cfg.dsn, "db.example.internal:1521/JDEPDB")
        self.assertEqual(cfg.user, "JDE_RO")
        self.assertEqual(cfg.password, "secret")
        self.assertEqual(cfg.default_rows, 200)
        self.assertEqual(cfg.max_rows, 2000)
        self.assertEqual(cfg.query_timeout_sec, 120)
        self.assertEqual(cfg.allowed_schemas, frozenset())

    def test_parses_allowed_schemas_and_default_schema(self) -> None:
        env = {
            "JDE_DB_DSN": "db.example.internal:1521/JDEPDB",
            "JDE_DB_USER": "JDE_RO",
            "JDE_DB_PASSWORD": "secret",
            "JDE_DEFAULT_SCHEMA": "proddta",
            "JDE_ALLOWED_SCHEMAS": "proddta, prodctl , sy920",
        }
        cfg = ServerConfig.from_env(env)
        self.assertEqual(cfg.default_schema, "PRODDTA")
        self.assertEqual(cfg.allowed_schemas, frozenset({"PRODDTA", "PRODCTL", "SY920"}))

    def test_rejects_missing_required_fields(self) -> None:
        with self.assertRaises(ConfigError):
            ServerConfig.from_env({})
        with self.assertRaises(ConfigError):
            ServerConfig.from_env({"JDE_DB_DSN": "host:1521/svc"})

    def test_rejects_invalid_row_limits(self) -> None:
        env = {
            "JDE_DB_DSN": "db.example.internal:1521/JDEPDB",
            "JDE_DB_USER": "JDE_RO",
            "JDE_DB_PASSWORD": "secret",
            "JDE_DEFAULT_ROWS": "5000",
            "JDE_MAX_ROWS": "2000",
        }
        with self.assertRaises(ConfigError):
            ServerConfig.from_env(env)

    def test_uses_keyring_lookup_when_password_not_in_env(self) -> None:
        env = {
            "JDE_DB_DSN": "db.example.internal:1521/JDEPDB",
            "JDE_DB_USER": "JDE_RO",
            "JDE_KEYRING_SERVICE": "jde-readonly-mcp",
        }
        calls: list[tuple[str, str]] = []

        def fake_keyring(service: str, user: str) -> str:
            calls.append((service, user))
            return "from-keyring"

        cfg = ServerConfig.from_env(env, keyring_getter=fake_keyring)
        self.assertEqual(cfg.password, "from-keyring")
        self.assertEqual(calls, [("jde-readonly-mcp", "JDE_RO")])


if __name__ == "__main__":
    unittest.main()
