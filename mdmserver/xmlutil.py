from __future__ import annotations

from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape


def xml_escape(value: object | None) -> str:
    return escape("" if value is None else str(value), {'"': "&quot;"})


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def iter_local(root: ET.Element, name: str):
    for element in root.iter():
        if local_name(element.tag) == name:
            yield element


def first_local(root: ET.Element, name: str) -> ET.Element | None:
    return next(iter_local(root, name), None)


def text_of(root: ET.Element, name: str, default: str = "") -> str:
    element = first_local(root, name)
    if element is None or element.text is None:
        return default
    return element.text.strip()


def attr_local(element: ET.Element, name: str, default: str = "") -> str:
    for key, value in element.attrib.items():
        if local_name(key) == name:
            return value
    return default


def parse_xml(data: bytes | str) -> ET.Element:
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    return ET.fromstring(data)
