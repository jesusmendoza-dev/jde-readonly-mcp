"""Secret redaction helpers for UDO XML/JSON definitions and audit parameters."""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEY_PART = (
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|"
    r"credential|private[_-]?key|client[_-]?secret|access[_-]?key)"
)

_XML_SECRET_TAG_RE = re.compile(
    rf"(<(?P<tag>[A-Za-z0-9_.:-]*{_SENSITIVE_KEY_PART}[A-Za-z0-9_.:-]*)[^>]*>)"
    r"([^<]+)"
    r"(</(?P=tag)>)",
    re.IGNORECASE,
)

_JSON_SECRET_RE = re.compile(
    rf'("[^"]*{_SENSITIVE_KEY_PART}[^"]*"\s*:\s*")([^"]*)(")',
    re.IGNORECASE,
)

_KV_SECRET_RE = re.compile(
    rf"(\b[A-Za-z0-9_.-]*{_SENSITIVE_KEY_PART}[A-Za-z0-9_.-]*\s*[=:]\s*)([^\s,;\"']+)",
    re.IGNORECASE,
)

_SENSITIVE_KEY_NAME_RE = re.compile(_SENSITIVE_KEY_PART, re.IGNORECASE)


def redact_secrets(text: str) -> str:
    """Mask likely secret values inside XML, JSON, or key-value text."""
    result = _XML_SECRET_TAG_RE.sub(rf"\1{REDACTED}\4", text)
    result = _JSON_SECRET_RE.sub(rf"\1{REDACTED}\3", result)
    result = _KV_SECRET_RE.sub(rf"\1{REDACTED}", result)
    return result


def redact_params(params: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow-sanitized copy of parameter dictionaries for audit logs."""
    sanitized: dict[str, Any] = {}
    for key, value in params.items():
        if _SENSITIVE_KEY_NAME_RE.search(str(key)):
            sanitized[key] = REDACTED
        elif isinstance(value, str):
            sanitized[key] = redact_secrets(value)
        else:
            sanitized[key] = value
    return sanitized
