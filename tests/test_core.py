import base64
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from burp_reader.grouping import group_exchanges
from burp_reader.redaction import redact_exchange
from burp_reader.rules import run_rules
from burp_reader.xml_reader import UnsafeXmlError, iter_burp_exchanges


class BurpReaderTests(unittest.TestCase):
    def test_parses_base64_and_redacts_credentials(self) -> None:
        request = b"GET /account?token=secret HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer abc\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: session=abc; Path=/\r\n\r\n<html>ok</html>"
        with TemporaryDirectory() as directory:
            xml_file = Path(directory) / "history.xml"
            xml_file.write_text(self._xml(request, response), encoding="utf-8")
            exchange = list(iter_burp_exchanges(xml_file))[0]
        redacted = redact_exchange(exchange)
        self.assertNotIn("secret", str(redacted))
        self.assertNotIn("Bearer abc", str(redacted))
        self.assertIn("[REDACTED]", str(redacted))
        titles = {finding.title for finding in run_rules(exchange)}
        self.assertIn("Cookie security attributes are incomplete", titles)
        self.assertIn("Recommended browser security headers are missing", titles)

    def test_groups_dynamic_paths(self) -> None:
        request = b"GET /users/1 HTTP/1.1\r\nHost: example.test\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        with TemporaryDirectory() as directory:
            first_file = Path(directory) / "first.xml"
            second_file = Path(directory) / "second.xml"
            first_file.write_text(self._xml(request, response, "/users/1"), encoding="utf-8")
            second_file.write_text(self._xml(request.replace(b"/1", b"/2"), response, "/users/2"), encoding="utf-8")
            first = list(iter_burp_exchanges(first_file))[0]
            second_original = list(iter_burp_exchanges(second_file))[0]
            second = replace(second_original, exchange_id=2)
        groups = group_exchanges([first, second], 10)
        self.assertEqual(1, len(groups))
        self.assertEqual((1, 2), groups[0].exchange_ids)

    def test_rejects_doctype(self) -> None:
        with TemporaryDirectory() as directory:
            xml_file = Path(directory) / "unsafe.xml"
            xml_file.write_text("<!DOCTYPE items><items></items>", encoding="utf-8")
            with self.assertRaises(UnsafeXmlError):
                list(iter_burp_exchanges(xml_file))

    def _xml(self, request: bytes, response: bytes, path: str = "/account") -> str:
        request_value = base64.b64encode(request).decode("ascii")
        response_value = base64.b64encode(response).decode("ascii")
        return (
            "<?xml version=\"1.0\"?><items><item>"
            f"<url>https://example.test{path}</url><host>example.test</host>"
            "<port>443</port><protocol>https</protocol><method>GET</method><status>200</status>"
            "<mimetype>HTML</mimetype>"
            f"<request base64=\"true\">{request_value}</request>"
            f"<response base64=\"true\">{response_value}</response>"
            "</item></items>"
        )


if __name__ == "__main__":
    unittest.main()
