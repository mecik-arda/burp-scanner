import base64
import re
from xml.etree.ElementTree import Element

from burp_reader.domain import HttpMessage


CHARSET_PATTERN = re.compile(r"charset\s*=\s*[\"']?([^;\s\"']+)", re.IGNORECASE)


def decode_burp_element(element: Element | None, max_bytes: int) -> HttpMessage:
    if element is None:
        return HttpMessage("", (), "", "")
    encoded_text = element.text or ""
    is_base64 = element.attrib.get("base64", "false").lower() == "true"
    payload = _decode_payload(encoded_text, is_base64)
    truncated = len(payload) > max_bytes
    bounded_payload = payload[:max_bytes]
    return parse_http_message(bounded_payload, truncated)


def _decode_payload(value: str, is_base64: bool) -> bytes:
    if not value:
        return b""
    if not is_base64:
        return value.encode("utf-8", errors="replace")
    compact_value = "".join(value.split())
    try:
        return base64.b64decode(compact_value, validate=True)
    except (ValueError, base64.binascii.Error):
        return value.encode("utf-8", errors="replace")


def parse_http_message(payload: bytes, truncated: bool = False) -> HttpMessage:
    header_bytes, body_bytes = _split_message(payload)
    header_text = header_bytes.decode("iso-8859-1", errors="replace")
    header_lines = header_text.replace("\r\n", "\n").split("\n") if header_text else []
    start_line = header_lines[0].strip() if header_lines else ""
    headers = tuple(_parse_headers(header_lines[1:]))
    charset = _detect_charset(headers)
    body = body_bytes.decode(charset, errors="replace")
    raw_text = header_text
    if body:
        raw_text = f"{header_text}\n\n{body}"
    return HttpMessage(start_line, headers, body, raw_text, truncated)


def _split_message(payload: bytes) -> tuple[bytes, bytes]:
    for separator in (b"\r\n\r\n", b"\n\n"):
        if separator in payload:
            return tuple(payload.split(separator, 1))
    return payload, b""


def _parse_headers(lines: list[str]) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for line in lines:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return headers


def _detect_charset(headers: tuple[tuple[str, str], ...]) -> str:
    for name, value in headers:
        if name.lower() != "content-type":
            continue
        match = CHARSET_PATTERN.search(value)
        if match:
            return match.group(1)
    return "utf-8"


def header_values(message: HttpMessage, header_name: str) -> tuple[str, ...]:
    normalized_name = header_name.lower()
    return tuple(value for name, value in message.headers if name.lower() == normalized_name)
