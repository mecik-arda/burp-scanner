import re

from burp_reader.domain import Finding, HttpExchange
from burp_reader.http_message import header_values


STACK_TRACE_PATTERNS = (
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"\bat [\w.$]+\([^\n]+:\d+\)", re.IGNORECASE),
    re.compile(r"System\.[A-Za-z]+Exception", re.IGNORECASE),
    re.compile(r"Stack trace:", re.IGNORECASE),
)
SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
)


def run_rules(exchange: HttpExchange) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_cookie_findings(exchange))
    findings.extend(_cors_findings(exchange))
    findings.extend(_header_findings(exchange))
    findings.extend(_body_findings(exchange))
    return findings


def _cookie_findings(exchange: HttpExchange) -> list[Finding]:
    findings: list[Finding] = []
    for cookie in header_values(exchange.response, "set-cookie"):
        cookie_name = cookie.split("=", 1)[0].strip() or "unnamed"
        normalized_cookie = cookie.lower()
        missing_flags = [
            flag
            for flag, marker in (("Secure", "; secure"), ("HttpOnly", "; httponly"), ("SameSite", "; samesite="))
            if marker not in normalized_cookie
        ]
        if not missing_flags:
            continue
        findings.append(
            Finding(
                source="rule",
                title="Cookie security attributes are incomplete",
                severity="medium",
                confidence="high",
                evidence=f"Cookie {cookie_name} is missing: {', '.join(missing_flags)}",
                recommendation="Set Secure, HttpOnly and an appropriate SameSite policy for session cookies.",
                exchange_ids=(exchange.exchange_id,),
                cwe="CWE-614",
            )
        )
    return findings


def _cors_findings(exchange: HttpExchange) -> list[Finding]:
    origins = tuple(value.strip() for value in header_values(exchange.response, "access-control-allow-origin"))
    credentials = tuple(value.lower() for value in header_values(exchange.response, "access-control-allow-credentials"))
    if "*" not in origins or "true" not in credentials:
        return []
    return [
        Finding(
            source="rule",
            title="CORS policy combines wildcard origin with credentials",
            severity="high",
            confidence="high",
            evidence="The response declares a wildcard origin and allows credentials.",
            recommendation="Use a strict origin allowlist and validate the Origin header server-side.",
            exchange_ids=(exchange.exchange_id,),
            cwe="CWE-942",
        )
    ]


def _header_findings(exchange: HttpExchange) -> list[Finding]:
    findings: list[Finding] = []
    disclosed_headers = [
        name
        for name in ("server", "x-powered-by", "x-aspnet-version")
        if header_values(exchange.response, name)
    ]
    if disclosed_headers:
        findings.append(
            Finding(
                source="rule",
                title="Technology information is exposed in response headers",
                severity="low",
                confidence="high",
                evidence=f"Present headers: {', '.join(disclosed_headers)}",
                recommendation="Remove unnecessary product and version disclosure headers.",
                exchange_ids=(exchange.exchange_id,),
                cwe="CWE-200",
            )
        )
    if not _is_html(exchange):
        return findings
    required_headers = {
        "content-security-policy": "Content-Security-Policy",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
    }
    missing = [display for name, display in required_headers.items() if not header_values(exchange.response, name)]
    if missing:
        findings.append(
            Finding(
                source="rule",
                title="Recommended browser security headers are missing",
                severity="low",
                confidence="high",
                evidence=f"Missing headers: {', '.join(missing)}",
                recommendation="Define the missing headers with policies appropriate to the application.",
                exchange_ids=(exchange.exchange_id,),
                cwe="CWE-693",
            )
        )
    return findings


def _body_findings(exchange: HttpExchange) -> list[Finding]:
    findings: list[Finding] = []
    body = exchange.response.body
    if any(pattern.search(body) for pattern in STACK_TRACE_PATTERNS):
        findings.append(
            Finding(
                source="rule",
                title="Response contains a stack trace indicator",
                severity="medium",
                confidence="medium",
                evidence="A known stack trace signature was detected without copying response content.",
                recommendation="Return generic errors to clients and keep diagnostic details in protected logs.",
                exchange_ids=(exchange.exchange_id,),
                cwe="CWE-209",
            )
        )
    if any(pattern.search(body) for pattern in SECRET_PATTERNS):
        findings.append(
            Finding(
                source="rule",
                title="Response may contain secret material",
                severity="high",
                confidence="medium",
                evidence="A credential-shaped value was detected and suppressed from the report.",
                recommendation="Verify the value, revoke it if active and remove it from client-visible responses.",
                exchange_ids=(exchange.exchange_id,),
                cwe="CWE-200",
            )
        )
    return findings


def _is_html(exchange: HttpExchange) -> bool:
    content_types = header_values(exchange.response, "content-type")
    return exchange.mime_type.lower() == "html" or any("text/html" in value.lower() for value in content_types)
