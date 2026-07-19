import base64
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from burp_reader.local_llm import LocalLlmClient, LocalLlmConfig
from burp_reader.pipeline import PipelineConfig, analyze
from burp_reader.reporting import write_reports


class PipelineTests(unittest.TestCase):
    def test_rules_only_pipeline_deduplicates_and_writes_reports(self) -> None:
        request = base64.b64encode(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n").decode("ascii")
        response = base64.b64encode(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: demo\r\n\r\n<html>ok</html>"
        ).decode("ascii")
        item = (
            "<item><url>https://example.test/</url><host>example.test</host>"
            "<port>443</port><protocol>https</protocol><method>GET</method><status>200</status>"
            "<mimetype>HTML</mimetype>"
            f"<request base64=\"true\">{request}</request>"
            f"<response base64=\"true\">{response}</response></item>"
        )
        with TemporaryDirectory() as directory:
            base_path = Path(directory)
            xml_file = base_path / "history.xml"
            markdown_file = base_path / "report.md"
            json_file = base_path / "report.json"
            xml_file.write_text(f"<items>{item}{item}</items>", encoding="utf-8")
            result = analyze(PipelineConfig(input_file=xml_file, rules_only=True))
            write_reports(result, markdown_file, json_file)
            report_data = json.loads(json_file.read_text(encoding="utf-8"))
        self.assertEqual(2, result.total_exchanges)
        self.assertEqual(2, len(result.findings))
        self.assertTrue(all(finding.exchange_ids == (1, 2) for finding in result.findings))
        self.assertEqual(2, len(report_data["findings"]))

    def test_remote_model_endpoint_requires_explicit_permission(self) -> None:
        config = LocalLlmConfig(
            provider="ollama",
            endpoint="https://model.example.test",
            model="test",
        )
        with self.assertRaises(ValueError):
            LocalLlmClient(config)


if __name__ == "__main__":
    unittest.main()
