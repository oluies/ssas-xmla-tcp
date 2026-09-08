"""The frame layer against REAL pyspnego output, not an XOR stand-in.

Every other sealing test uses a reversible fake, which proves the arithmetic but
not the contract: that `wrap_winrm` returns (token, ciphertext, padding_length)
with the ciphertext at plaintext length, and that `unwrap_winrm(token, ciphertext)`
inverts it. If pyspnego ever changed that shape, the fakes would keep passing and
only a live server would notice.

pyspnego can run a client and a server context against each other in-process over
NTLM with no KDC and no network, so this costs nothing to run offline. It does NOT
cover Kerberos crypto -- that needs a KDC, see ARCHITECTURE "Verifying Kerberos".
What it does cover is the wrap/unwrap contract the frame layer depends on, which
is mechanism-independent.
"""

import pytest

from ssas_xmla import sealing

spnego = pytest.importorskip("spnego", reason="pyspnego is the one runtime dependency")


@pytest.fixture
def negotiated_pair(tmp_path, monkeypatch):
    """A completed client/server NTLM context pair, handshaked in memory.

    The acceptor needs a credential cache, which pyspnego reads from NTLM_USER_FILE
    as `domain:user:password` lines. Written per-test into pytest's tmp_path, with
    a value that is not a credential anywhere -- nothing here reaches the tree.
    """
    domain, user = "TESTDOM", "tester"
    secret = "pw-" + "for-a-fake-acceptor"
    cache = tmp_path / "ntlm_creds"
    cache.write_text(f"{domain}:{user}:{secret}\n")
    cache.chmod(0o600)
    monkeypatch.setenv("NTLM_USER_FILE", str(cache))

    client = spnego.client(
        f"{domain}\\{user}",
        secret,
        hostname="localhost",
        service="host",
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )
    server = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
    token = client.step()
    while not (client.complete and server.complete):
        token = server.step(token)
        if token is None:
            break
        token = client.step(token)
        if token is None:
            break
    if not (client.complete and server.complete):
        pytest.skip("this pyspnego build cannot complete an in-process NTLM handshake")
    return client, server


def test_wrap_winrm_returns_the_detached_shape_the_frame_depends_on(negotiated_pair):
    """ADOMD's layout needs the ciphertext at PLAINTEXT length in its own buffer,
    with the token separate. That is what makes `dataSize` meaningful."""
    client, _ = negotiated_pair
    payload = b"<Envelope>real crypto</Envelope>"
    token, ciphertext, padding_length = client.wrap_winrm(payload)
    assert len(ciphertext) == len(payload)  # length-preserving, so dataSize == len(plaintext)
    assert padding_length == 0  # NTLM; a padding mechanism is refused by seal_frame
    assert len(token) == 16  # NTLM's signature; Kerberos differs, and must not be assumed


def test_a_real_frame_decodes_to_the_declared_sizes(negotiated_pair):
    import struct

    client, _ = negotiated_pair
    frame = sealing.seal_frame(client, b"hello")
    data_size, token_size = struct.unpack_from("<HH", frame, 0)
    assert data_size == 5
    assert len(frame) == 4 + data_size + token_size
    assert frame[4 : 4 + data_size] != b"hello"  # actually encrypted


def test_a_whole_message_round_trips_through_real_contexts(negotiated_pair):
    """Seal with the client, unseal with the server -- the direction a request
    actually travels. A fake context cannot catch a sequence-number or keystream
    mistake because it has neither."""
    client, server = negotiated_pair
    payload = b"<Envelope>" + b"x" * 9000 + b"</Envelope>"
    message = sealing.seal_message(client, payload)
    assert sealing.unseal_message(server, message) == payload


def test_keystream_continuity_across_chunks(negotiated_pair):
    """RC4 keystream and the sequence counter advance per frame, so a message
    chunked into several frames only decodes if every frame is unwrapped in order.
    This is the failure an XOR fake is structurally incapable of detecting."""
    client, server = negotiated_pair
    payload = b"y" * (sealing.MAX_CHUNK * 2 + 7)
    message = sealing.seal_message(client, payload)
    assert sealing.unseal_message(server, message) == payload
