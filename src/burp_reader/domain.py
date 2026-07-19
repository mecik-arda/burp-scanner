from dataclasses import dataclass, field


@dataclass(frozen=True)
class HttpMessage:
    start_line: str
    headers: tuple[tuple[str, str], ...]
    body: str
    raw_text: str
    truncated: bool = False


@dataclass(frozen=True)
class HttpExchange:
    exchange_id: int
    url: str
    method: str
    host: str
    port: int | None
    protocol: str
    status: int | None
    mime_type: str
    comment: str
    request: HttpMessage
    response: HttpMessage


@dataclass(frozen=True)
class ExchangeGroup:
    fingerprint: str
    representative: HttpExchange
    exchange_ids: tuple[int, ...]


@dataclass(frozen=True)
class Finding:
    source: str
    title: str
    severity: str
    confidence: str
    evidence: str
    recommendation: str
    exchange_ids: tuple[int, ...]
    cwe: str = ""


@dataclass
class AnalysisResult:
    total_exchanges: int = 0
    in_scope_exchanges: int = 0
    analyzed_groups: int = 0
    model_provider: str = ""
    model_name: str = ""
    model_device: str = ""
    duration_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
