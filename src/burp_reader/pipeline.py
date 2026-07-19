from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from burp_reader.domain import AnalysisResult, Finding, HttpExchange
from burp_reader.grouping import group_exchanges
from burp_reader.local_llm import LocalLlmClient, LocalLlmConfig, LocalLlmConnectionError
from burp_reader.rules import run_rules
from burp_reader.xml_reader import iter_burp_exchanges


@dataclass(frozen=True)
class PipelineConfig:
    input_file: Path
    allowed_hosts: tuple[str, ...] = ()
    max_message_bytes: int = 1_000_000
    max_items: int = 100_000
    max_groups: int = 200
    rules_only: bool = False
    llm: LocalLlmConfig | None = None


def analyze(config: PipelineConfig) -> AnalysisResult:
    started_at = perf_counter()
    result = AnalysisResult(
        model_provider="rules-only" if config.rules_only else config.llm.provider if config.llm else "",
        model_name="" if config.rules_only or config.llm is None else config.llm.model,
        model_device="" if config.rules_only or config.llm is None else config.llm.device,
    )
    scoped_exchanges: list[HttpExchange] = []
    allowed_hosts = {host.lower() for host in config.allowed_hosts}
    for exchange in iter_burp_exchanges(config.input_file, config.max_message_bytes, config.max_items):
        result.total_exchanges += 1
        if allowed_hosts and exchange.host.lower() not in allowed_hosts:
            continue
        result.in_scope_exchanges += 1
        scoped_exchanges.append(exchange)
        result.findings.extend(run_rules(exchange))
    groups = group_exchanges(scoped_exchanges, config.max_groups)
    if config.rules_only:
        result.findings = _deduplicate_findings(result.findings)
        result.duration_seconds = round(perf_counter() - started_at, 3)
        return result
    if config.llm is None:
        raise ValueError("Local LLM configuration is required unless --rules-only is used")
    client = LocalLlmClient(config.llm)
    for group in groups:
        try:
            result.findings.extend(client.analyze(group))
            result.analyzed_groups += 1
        except LocalLlmConnectionError as error:
            result.errors.append(str(error))
            break
        except (RuntimeError, ValueError) as error:
            result.errors.append(f"Group {group.fingerprint}: {error}")
    result.findings = _deduplicate_findings(result.findings)
    result.duration_seconds = round(perf_counter() - started_at, 3)
    return result


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple[str, ...], Finding] = {}
    for finding in findings:
        key = (
            finding.source,
            finding.title,
            finding.severity,
            finding.confidence,
            finding.evidence,
            finding.recommendation,
            finding.cwe,
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        exchange_ids = tuple(sorted(set(existing.exchange_ids + finding.exchange_ids)))
        merged[key] = finding.__class__(
            source=finding.source,
            title=finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence=finding.evidence,
            recommendation=finding.recommendation,
            exchange_ids=exchange_ids,
            cwe=finding.cwe,
        )
    return list(merged.values())
