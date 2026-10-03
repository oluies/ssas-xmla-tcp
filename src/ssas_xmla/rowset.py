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


def _cell(element: ET.Element) -> str:
    """One cell's value: its text, or the cell itself serialised when it carries
    elements.

    A metadata rowset can put a whole XML document INSIDE a cell rather than a
    scalar: DISCOVER_CSDL_METADATA returns the model's CSDL as element children of
    <METADATA>, and DISCOVER_XML_METADATA does the same with ASSL. `element.text`
    is then empty or whitespace, so reading only text discarded the entire payload
    and produced a row with a blank cell -- indistinguishable, to every consumer,
    from a server that sent nothing. The OpenMetadata connector's tabular path
    ingested a database, a schema and zero tables that way, and reported success.

    The CELL is serialised, not its children. Concatenating children produced a
    multi-root fragment for any cell carrying more than one, which is not a
    document and raises on ET.fromstring -- and that is not hypothetical: the
    `Restrictions` cell of DISCOVER_SCHEMA_ROWSETS holds `<Name>` and `<Type>`
    side by side. Keeping the cell as the root means the value always parses, and
    the root's name is one the server actually sent rather than a synthetic
    wrapper.

    It is a RE-serialisation, not the bytes from the wire: ElementTree rewrites a
    default namespace to a generated prefix, so `<Schema xmlns="...edm">` comes
    back as `<ns0:Schema xmlns:ns0="...edm">`. Consumers that match on local names
    or namespace URIs are unaffected; one matching literal markup is not.
    """
    if not len(element):
        return element.text or ""
    return ET.tostring(element, encoding="unicode")


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

    def take(element: ET.Element) -> None:
        row = {}
        for child in element:
            name = _local(child.tag)
            row[name] = _cell(child)
            if name not in columns:
                columns.append(name)
        rows.append(row)

    def walk(element: ET.Element) -> None:
        """Find rows without descending INTO one.

        `root.iter()` walked the whole tree, which contradicts what a cell now is:
        a subtree that may itself contain elements named `row`. Those would be
        emitted a second time as top-level rows, with their names appended to
        `columns`, while the same content sits correctly inside the parent row's
        cell.
        """
        for child in element:
            if _local(child.tag) == "row":
                take(child)
            else:
                walk(child)

    if _local(root.tag) == "row":
        take(root)
    else:
        walk(root)
    return Rowset(columns=columns, rows=rows)
