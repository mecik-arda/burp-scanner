import hashlib
import re
from urllib.parse import urlsplit

from burp_reader.domain import ExchangeGroup, HttpExchange


UUID_PATTERN = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b")
LONG_HEX_PATTERN = re.compile(r"(?i)\b[0-9a-f]{16,}\b")
NUMBER_SEGMENT_PATTERN = re.compile(r"(?<=/)\d+(?=/|$)")


def group_exchanges(exchanges: list[HttpExchange], max_groups: int) -> list[ExchangeGroup]:
    grouped: dict[str, list[HttpExchange]] = {}
    for exchange in exchanges:
        fingerprint = exchange_fingerprint(exchange)
        grouped.setdefault(fingerprint, []).append(exchange)
    groups = [
        ExchangeGroup(
            fingerprint=fingerprint,
            representative=members[0],
            exchange_ids=tuple(member.exchange_id for member in members),
        )
        for fingerprint, members in grouped.items()
    ]
    return groups[:max_groups]


def exchange_fingerprint(exchange: HttpExchange) -> str:
    try:
        path = urlsplit(exchange.url).path
    except ValueError:
        path = exchange.url
    normalized_path = UUID_PATTERN.sub("{uuid}", path)
    normalized_path = LONG_HEX_PATTERN.sub("{hex}", normalized_path)
    normalized_path = NUMBER_SEGMENT_PATTERN.sub("{id}", normalized_path)
    status_family = exchange.status // 100 if exchange.status is not None else 0
    identity = "|".join(
        (exchange.method.upper(), exchange.host.lower(), normalized_path, str(status_family))
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"{identity}|{digest}"
