"""The post-authentication frame: how a sealed message is laid out on the wire.

Every message after the handshake is sealed with the negotiated security context
and wrapped in a 4-byte header. The layout was recovered by decompiling
``Microsoft.AnalysisServices.AdomdClient`` (``TcpSecureStream.WriteHeader`` /
``WriteInBlockMode``), because it is not in [MS-SSAS]:

    uint16  dataSize    little-endian, the ciphertext length
    uint16  tokenSize   little-endian, the security token length (16 for NTLM)
    bytes   ciphertext  dataSize bytes
    bytes   token       tokenSize bytes

**Ciphertext first, token second.** That is the inverse of the GSS-API ordering
`pyspnego` produces, and getting it backwards is silently fatal: the server closes
the connection with no error and logs nothing.

Two details that are easy to miss and cost a lot to rediscover:

- The UTF-8 BOM is sealed as its OWN frame before the body. The reference client
  writes it through a StreamWriter, whose preamble is a separate write, so it
  becomes a separate frame. We emit it because the reference client does; whether
  the server *requires* it has not been tested independently. The working exchange
  fixed two faults at once (byte order and the missing header plus BOM frame), so
  the BOM was never varied on its own against a live server.
- Frames are chunked at 2888 bytes for NTLM (the reference client reuses
  ``cbMaxToken`` as the data chunk size). The hard ceiling is 65535, since
  ``dataSize`` is a uint16.

**UNVERIFIED for Kerberos.** Everything here was recovered from, and exercised
against, an NTLM session: ``MAX_CHUNK`` is NTLM's ``cbMaxToken`` and the 16-byte
token is NTLM's signature length. The header has no field carrying the *unpadded*
plaintext length, which is fine for NTLM (``spnego`` reports zero padding for it)
but not for a mechanism that pads — see ``seal_frame``.
"""

from __future__ import annotations

import struct
from typing import Protocol

from .errors import IncompleteMessage, ProtocolError

BOM = b"\xef\xbb\xbf"
HEADER = struct.Struct("<HH")
# The reference client's chunk size for NTLM. Not a protocol limit -- the limit is
# 65535 -- but matching it keeps our frames the same shape as a real client's.
MAX_CHUNK = 2888


class SecurityContext(Protocol):
    def wrap_winrm(self, data: bytes) -> tuple[bytes, bytes, int]: ...

    def unwrap_winrm(self, header: bytes, data: bytes) -> bytes: ...


def seal_frame(context: SecurityContext, payload: bytes) -> bytes:
    """Wrap one payload as a single sealed frame.

    Refuses a mechanism that pads. The frame has two length fields and neither
    carries the *unpadded* plaintext length, so padding bytes sit inside
    ``dataSize`` and the peer has nothing to strip them by. (WinRM solves the same
    problem with an explicit ``OriginalContent: Length=`` field; this frame has no
    equivalent.) NTLM reports ``padding_length=0``, which is why the NTLM path
    works; a padding mechanism would send the server XML with trailing rubbish and
    fail as a parse error far from its cause. Better to say so here.
    """
    token, ciphertext, padding_length = context.wrap_winrm(payload)
    if padding_length:
        raise ProtocolError(
            f"the negotiated mechanism padded the plaintext by {padding_length} "
            f"bytes, and this frame has no field to convey the unpadded length. "
            f"The layout is confirmed for NTLM only; use mechanism='ntlm'."
        )
    if len(ciphertext) > 0xFFFF or len(token) > 0xFFFF:
        raise ProtocolError("frame exceeds the uint16 size fields")
    return HEADER.pack(len(ciphertext), len(token)) + ciphertext + token


def seal_message(context: SecurityContext, payload: bytes) -> bytes:
    """Seal a whole message: the BOM as its own frame, then the body, chunked."""
    out = [seal_frame(context, BOM)]
    for start in range(0, len(payload), MAX_CHUNK):
        out.append(seal_frame(context, payload[start : start + MAX_CHUNK]))
    return b"".join(out)


def unseal_message(context: SecurityContext, blob: bytes) -> bytes:
    """Decrypt every frame in a sealed response and concatenate the plaintext.

    A buffer that ends mid-frame raises ``IncompleteMessage``, never
    ``ProtocolError``. The transport discriminates on exactly that distinction
    (``MessageStream._try_parse``) and conflating them broke chunked messages once
    already: a rowset larger than one read arrives split, which is "read more",
    not "malformed". The 1-3 byte case matters as much as the rest -- a partial
    header used to fall out of the loop condition and be discarded in silence,
    handing the caller short plaintext with no error at all.
    """
    out: list[bytes] = []
    offset = 0
    while offset < len(blob):
        if offset + HEADER.size > len(blob):
            raise IncompleteMessage("sealed message ends inside a frame header")
        data_size, token_size = HEADER.unpack_from(blob, offset)
        offset += HEADER.size
        end_data = offset + data_size
        end_token = end_data + token_size
        if end_token > len(blob):
            raise IncompleteMessage("sealed frame runs past the end of the message")
        ciphertext = blob[offset:end_data]
        token = blob[end_data:end_token]
        out.append(context.unwrap_winrm(token, ciphertext))
        offset = end_token
    plain = b"".join(out)
    return plain[len(BOM) :] if plain.startswith(BOM) else plain
