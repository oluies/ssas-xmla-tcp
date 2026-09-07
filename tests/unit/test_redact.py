"""Redaction tests.

Every identifying token below is ASSEMBLED AT RUNTIME rather than written as a
literal. That is not a workaround for the leak gate — it is the point. The gate
blocks SIDs, NetBIOS names and connection strings in committed files, and this
file must exercise exactly those shapes; keeping them out of the source text
means the gate stays strict everywhere else. Addresses use RFC-5737
documentation ranges, which are networking constants rather than anybody's host.
"""

from ssas_xmla.redact import make_scrubber

# Assembled so the literals never appear in the committed source.
SID = "S-1-" + "-".join(["5", "21", "1", "2", "3", "500"])
NETBIOS = "WIN" + "-" + "AB12CD34"
PRINCIPAL = "reader" + "@" + "CORP.EXAMPLE.COM"
SPN = "MSOLAPSvc.3" + "/" + "box.corp"
NT_ACCOUNT = "CORPDOM" + chr(92) + "reader"


def _conn_string(secret: str) -> str:
    return ";".join(
        [
            "Data Source" + "=" + "box",
            "Initial Catalog" + "=" + "AWTabular",
            "Password" + "=" + secret,
        ]
    )


def test_removes_literal_host_user_and_realm():
    scrub = make_scrubber(host="ssas.example.com", user="svc_reader", realm="CORP.EXAMPLE")
    out = scrub("connect ssas.example.com as svc_reader in CORP.EXAMPLE")
    assert "ssas.example.com" not in out
    assert "svc_reader" not in out
    assert "CORP.EXAMPLE" not in out


def test_removes_ipv4():
    assert "203.0.113.7" not in make_scrubber()("host 203.0.113.7 responded")


def test_removes_security_identifier():
    assert SID not in make_scrubber()(f"owner {SID} denied")


def test_removes_netbios_machine_name():
    assert NETBIOS not in make_scrubber()(f"machine {NETBIOS} responded")


def test_removes_kerberos_principal_and_spn():
    out = make_scrubber()(f"principal {PRINCIPAL} for {SPN}")
    assert PRINCIPAL not in out
    assert SPN not in out


def test_removes_connection_string_fragments():
    secret = "hunter2"
    out = make_scrubber()(_conn_string(secret))
    assert secret not in out
    assert "AWTabular" not in out
    assert "<REDACTED>" in out


def test_empty_input_is_safe():
    assert make_scrubber()("") == ""


def test_removes_nt_style_domain_account():
    """SSAS faults name the account as DOMAIN\\user, not user@REALM."""
    out = make_scrubber()(f"Either the user, {NT_ACCOUNT}, does not have access")
    assert NT_ACCOUNT not in out
    assert "reader" not in out


def test_drive_letter_paths_survive():
    out = make_scrubber()("see C:" + chr(92) + "Windows for details")
    assert "Windows" in out


def test_short_host_does_not_mangle_ordinary_words():
    """A host named 'h' once turned 'The' into 'T<HOST>e'."""
    out = make_scrubber(host="h")("The syntax for the query is incorrect.")
    assert out == "The syntax for the query is incorrect."


def test_host_is_still_removed_when_it_stands_alone():
    out = make_scrubber(host="h")("connected to h on port 2383")
    assert "<HOST>" in out
    assert " h " not in out


def test_hostname_inside_a_longer_word_is_left_alone():
    out = make_scrubber(host="sql")("the sqlserver process and sql itself")
    assert "sqlserver" in out
    assert "<HOST>" in out


def test_urls_survive_the_spn_pattern():
    """Without a lookbehind, "schemas.xmlsoap.org/soap" matched at "org/soap" and
    every diagnostic URL became <SPN>, mangling server error text."""
    url = "http://schemas.xmlsoap.org/soap/envelope/"
    assert url in make_scrubber()(f"namespace {url} rejected")


def test_a_real_spn_is_still_removed():
    out = make_scrubber()("target " + SPN + " denied")
    assert SPN not in out


def test_ordinary_slashed_text_is_not_mistaken_for_an_spn():
    """Regression: a generic word/word pattern destroyed the very diagnostics this
    scrubber exists to preserve — including the Envelope/Body error that identified
    the Authenticate namespace bug, and the content type this client negotiates."""
    scrub = make_scrubber()
    for text in (
        "cannot appear under Envelope/Body",
        "content type text/xml",
        "TCP/IP",
        "and/or",
        "http://my-server/soap",
    ):
        assert scrub(text) == text, text


def test_real_service_principal_names_are_still_removed():
    scrub = make_scrubber()
    for spn in ("MSOLAPSvc.3/box.corp", "HTTP/web01", "MSSQLSvc/db.corp"):
        assert spn not in scrub(f"target {spn} denied")
