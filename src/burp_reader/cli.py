import argparse
import os
from pathlib import Path

from burp_reader.local_llm import LocalLlmConfig
from burp_reader.pipeline import PipelineConfig, analyze
from burp_reader.reporting import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="burp-reader")
    parser.add_argument("-f", "--file", type=Path, required=True)
    parser.add_argument("-o", "--output", type=Path, default=Path("reports/report.md"))
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--provider", choices=("openvino", "ollama", "openai"), default=os.getenv("BURP_READER_PROVIDER", "openvino"))
    parser.add_argument("--endpoint", default=os.getenv("BURP_READER_LLM_ENDPOINT"))
    parser.add_argument("--model", default=os.getenv("BURP_READER_MODEL"))
    parser.add_argument("--device", default=os.getenv("BURP_READER_OPENVINO_DEVICE", "GPU"))
    parser.add_argument("--cache-directory", default=os.getenv("BURP_READER_OPENVINO_CACHE", ".openvino_cache"))
    parser.add_argument("--allowed-host", action="append", default=[])
    parser.add_argument("--max-message-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-items", type=int, default=100_000)
    parser.add_argument("--max-groups", type=int, default=200)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--language", default="tr")
    parser.add_argument("--rules-only", action="store_true")
    parser.add_argument("--allow-remote-model", action="store_true")
    return parser


def main() -> None:
    arguments = build_parser().parse_args()
    endpoint = arguments.endpoint or _default_endpoint(arguments.provider)
    model = arguments.model or _default_model(arguments.provider)
    json_output = arguments.json_output or arguments.output.with_suffix(".json")
    llm_config = LocalLlmConfig(
        provider=arguments.provider,
        endpoint=endpoint,
        model=model,
        timeout_seconds=arguments.timeout,
        allow_remote=arguments.allow_remote_model,
        language=arguments.language,
        device=arguments.device,
        cache_directory=arguments.cache_directory,
    )
    config = PipelineConfig(
        input_file=arguments.file,
        allowed_hosts=tuple(arguments.allowed_host),
        max_message_bytes=arguments.max_message_bytes,
        max_items=arguments.max_items,
        max_groups=arguments.max_groups,
        rules_only=arguments.rules_only,
        llm=llm_config,
    )
    result = analyze(config)
    write_reports(result, arguments.output, json_output)
    print(f"Markdown report: {arguments.output}")
    print(f"JSON report: {json_output}")
    print(f"Findings: {len(result.findings)}")
    if result.errors:
        print(f"Analysis errors: {len(result.errors)}")


def _default_endpoint(provider: str) -> str:
    if provider == "ollama":
        return "http://127.0.0.1:11434"
    if provider == "openai":
        return "http://127.0.0.1:1234"
    return ""


def _default_model(provider: str) -> str:
    if provider == "openvino":
        return "models/Qwen-2.5-7B-Instruct-INT4"
    if provider == "ollama":
        return "qwen3.5:9b"
    return "local-model"
