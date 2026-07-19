import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from burp_reader.domain import HttpExchange, HttpMessage


SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
}
SENSITIVE_KEY_PATTERN = re.compile(
    r'(?i)(["\']?(?:password|passwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token)["\']?\s*[:=]\s*["\']?)([^"\'&\s,}]+)'
)
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
SENSITIVE_QUERY_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
}


def redact_exchange(exchange: HttpExchange) -> dict[str, object]:
    return {
        "id": exchange.exchange_id,
        "url": redact_url(exchange.url),
        "method": exchange.method,
        "host": exchange.host,
        "status": exchange.status,
        "mime_type": exchange.mime_type,
        "request": redact_message(exchange.request),
        "response": redact_message(exchange.response),
    }


def redact_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        query = [
            (key, "[REDACTED]" if key.lower() in SENSITIVE_QUERY_KEYS else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))
    except ValueError:
        return "[INVALID_URL]"


def redact_message(message: HttpMessage) -> str:
    lines = [_redact_start_line(message.start_line)] if message.start_line else []
    for name, value in message.headers:
        normalized_name = name.lower()
        if normalized_name in SENSITIVE_HEADERS:
            safe_value = "[REDACTED]"
        elif normalized_name == "set-cookie":
            safe_value = _redact_set_cookie(value)
        else:
            safe_value = redact_text(value)
        lines.append(f"{name}: {safe_value}")
    if message.body:
        lines.extend(("", redact_text(message.body)))
    if message.truncated:
        lines.extend(("", "[CONTENT_TRUNCATED]"))
    return "\n".join(lines)


def redact_text(value: str) -> str:
    redacted = SENSITIVE_KEY_PATTERN.sub(r"\1[REDACTED]", value)
    redacted = BEARER_PATTERN.sub("Bearer [REDACTED]", redacted)
    redacted = JWT_PATTERN.sub("[REDACTED_JWT]", redacted)
    return EMAIL_PATTERN.sub("[REDACTED_EMAIL]", redacted)


def _redact_set_cookie(value: str) -> str:
    parts = value.split(";")
    cookie_name = parts[0].split("=", 1)[0].strip()
    attributes = [part.strip() for part in parts[1:] if part.strip()]
    safe_parts = [f"{cookie_name}=[REDACTED]", *attributes]
    return "; ".join(safe_parts)


def _redact_start_line(value: str) -> str:
    parts = value.split(" ", 2)
    if len(parts) != 3 or not parts[0].isalpha():
        return redact_text(value)
    return f"{parts[0]} {redact_url(parts[1])} {parts[2]}"
