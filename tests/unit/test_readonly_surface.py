"""Constitution II: read-only BY CONSTRUCTION, not by convention.

These assert the capability is absent from the codebase, so no argument, flag or
mistake can reach a mutating command.
"""
import inspect
from pathlib import Path

from ssas_xmla import client, envelopes

FORBIDDEN = ("create", "alter", "delete", "refresh", "process", "tmsl", "drop", "update")
SRC = Path(client.__file__).parent


def test_no_public_entry_point_names_a_mutating_operation():
    for module in (client, envelopes):
        for name in dir(module):
            if name.startswith("_"):
                continue
            assert not any(f in name.lower() for f in FORBIDDEN), f"{module.__name__}.{name}"


def test_session_exposes_only_read_operations():
    public = [n for n in dir(client.Session) if not n.startswith("_")]
    assert set(public) <= {
        "open", "close", "discover", "discover_datasources", "execute",
        "target", "credential", "terms", "state",
    }, public


def test_no_module_constructs_a_tmsl_or_ddl_command():
    """A grep-level guarantee: the strings simply are not in the library."""
    for path in SRC.glob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        for token in ("<create", "<alter", "<delete", "<refresh", "createorreplace"):
            assert token not in text, f"{path.name} contains {token}"


def test_execute_signature_offers_no_mutating_switch():
    sig = inspect.signature(client.Session.execute)
    assert list(sig.parameters) == ["self", "statement", "catalog"]
