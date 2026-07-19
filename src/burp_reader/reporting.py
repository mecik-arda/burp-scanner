import json
from dataclasses import asdict
from pathlib import Path

from burp_reader.domain import AnalysisResult, Finding


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def write_reports(result: AnalysisResult, markdown_path: Path, json_path: Path) -> None:
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(_render_markdown(result), encoding="utf-8")
    json_path.write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2), encoding="utf-8")


def _render_markdown(result: AnalysisResult) -> str:
    findings = sorted(result.findings, key=lambda finding: SEVERITY_ORDER.get(finding.severity, 5))
    lines = [
        "# Burp Reader Security Report",
        "",
        "## Summary",
        "",
        f"- Parsed exchanges: {result.total_exchanges}",
        f"- In-scope exchanges: {result.in_scope_exchanges}",
        f"- Local-model groups analyzed: {result.analyzed_groups}",
        f"- Model provider: {result.model_provider or 'Not configured'}",
        f"- Model: {result.model_name or 'Not used'}",
        f"- Device: {result.model_device or 'Not used'}",
        f"- Duration: {result.duration_seconds:.3f} seconds",
        f"- Findings: {len(findings)}",
        f"- Analysis errors: {len(result.errors)}",
        "",
        "Model-generated findings are candidates and require manual verification.",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.extend(("No findings were produced.", ""))
    for index, finding in enumerate(findings, 1):
        lines.extend(_render_finding(index, finding))
    if result.errors:
        lines.extend(("## Analysis Errors", ""))
        for error in result.errors:
            lines.append(f"- {error}")
        lines.append("")
    return "\n".join(lines)


def _render_finding(index: int, finding: Finding) -> list[str]:
    cwe_line = f"- CWE: {finding.cwe}" if finding.cwe else "- CWE: Not assigned"
    return [
        f"### {index}. {finding.title}",
        "",
        f"- Severity: {finding.severity}",
        f"- Confidence: {finding.confidence}",
        f"- Source: {finding.source}",
        f"- Exchange IDs: {', '.join(str(value) for value in finding.exchange_ids)}",
        cwe_line,
        "",
        "Evidence:",
        "",
        finding.evidence,
        "",
        "Recommendation:",
        "",
        finding.recommendation,
        "",
    ]
