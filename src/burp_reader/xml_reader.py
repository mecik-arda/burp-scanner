from collections.abc import Iterator
from pathlib import Path
import xml.etree.ElementTree as ET

from burp_reader.domain import HttpExchange
from burp_reader.http_message import decode_burp_element


FORBIDDEN_XML_DECLARATIONS = (b"<!doctype", b"<!entity")


class UnsafeXmlError(ValueError):
    pass


def iter_burp_exchanges(
    file_path: Path,
    max_message_bytes: int = 1_000_000,
    max_items: int = 100_000,
) -> Iterator[HttpExchange]:
    _reject_unsafe_xml(file_path)
    exchange_id = 0
    for _, element in ET.iterparse(file_path, events=("end",)):
        if _local_name(element.tag) != "item":
            continue
        exchange_id += 1
        if exchange_id > max_items:
            raise ValueError(f"XML item limit exceeded: {max_items}")
        children = {_local_name(child.tag): child for child in element}
        yield HttpExchange(
            exchange_id=exchange_id,
            url=_text(children.get("url")),
            method=_text(children.get("method")),
            host=_text(children.get("host")),
            port=_integer(_text(children.get("port"))),
            protocol=_text(children.get("protocol")),
            status=_integer(_text(children.get("status"))),
            mime_type=_text(children.get("mimetype")),
            comment=_text(children.get("comment")),
            request=decode_burp_element(children.get("request"), max_message_bytes),
            response=decode_burp_element(children.get("response"), max_message_bytes),
        )
        element.clear()


def _reject_unsafe_xml(file_path: Path) -> None:
    overlap = b""
    with file_path.open("rb") as source:
        while chunk := source.read(65_536):
            lowered = (overlap + chunk).lower()
            if any(marker in lowered for marker in FORBIDDEN_XML_DECLARATIONS):
                raise UnsafeXmlError("DTD and entity declarations are not accepted")
            overlap = lowered[-16:]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(element: ET.Element | None) -> str:
    return (element.text or "").strip() if element is not None else ""


def _integer(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None
