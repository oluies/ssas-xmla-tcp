"""Parse an XMLA response into rows, and surface a SOAP fault as one.

Values stay strings: interpreting them is the caller's business, and the
OpenMetadata connector already owns that mapping for its own purposes.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

_FAULT = re.compile(r"<faultstring>(.*?)</faultstring>", re.S)
_FAULTCODE = re.compile(r"<faultcode>(.*?)</faultcode>", re.S)


@dataclass(frozen=True)
class Rowset:
    """Ordered column names plus rows of string values."""

    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, str]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rows)

    def __iter__(self):
        return iter(self.rows)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def find_fault(text: str) -> tuple[str | None, str | None]:
    """Return (faultcode, faultstring) if the response carries a SOAP fault."""
    if "<Fault" not in text and "faultcode" not in text:
        return None, None
    code = _FAULTCODE.search(text)
    message = _FAULT.search(text)
    return (
        code.group(1).strip() if code else None,
        message.group(1).strip() if message else None,
    )


def parse(text: str) -> Rowset:
    """Parse an XMLA rowset response.

    Matches on local element names so the default `...:rowset` namespace needs no
    special handling.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return Rowset()
    rows: list[dict[str, str]] = []
    columns: list[str] = []
    for element in root.iter():
        if _local(element.tag) != "row":
            continue
        row = {}
        for child in element:
            name = _local(child.tag)
            row[name] = child.text or ""
            if name not in columns:
                columns.append(name)
        rows.append(row)
    return Rowset(columns=columns, rows=rows)
