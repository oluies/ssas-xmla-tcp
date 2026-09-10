---
title: Troubleshooting
sidebar_position: 4
---

# Troubleshooting

Start with the probe. It names the stage that failed, which is most of the diagnosis:

```bash
python -m ssas_xmla.probe --host ssas.example.com --port 2383 --mechanism ntlm
echo "exit $?"
```

## The connection hangs

Most often the port is wrong. There is no default port and no redirector, so a connection to a
named instance's *old* dynamic port, or to 2382 expecting a redirect, will sit there.

Pin the port in the instance's `msmdsrv.ini`, restart it, and confirm with a plain TCP
connect:

```bash
python -c "import socket; socket.create_connection(('ssas.example.com', 2383), 5)" && echo reachable
```

## "AUTHENTICATION FAILED — check ticket or keytab" on a named instance

This message points at the wrong cause when the real problem is the **SPN**. A named instance
registered as `MSOLAPSvc.3/host:TAB` is not what the default portless form asks for.

The probe prints the SPN the run actually requested. If it does not match how the instance is
registered:

```bash
python -m ssas_xmla.probe --host ssas.example.com --port 2383 --instance TAB
```

Under **NTLM this cannot be the cause** — NTLM ignores the SPN entirely, so check the account
and `$SSAS_PASSWORD` instead.

## `ProtocolError` mentioning padding, after a successful handshake

The negotiated mechanism pads the plaintext, and the sealed frame has no field for the
unpadded length. Retry with `--mechanism ntlm`.

This is a known, named limitation rather than a bug — see
[Why padding cannot be framed](../protocol/sealing.md#why-padding-cannot-be-framed).

## The connection closes with no error and nothing in the server log

The characteristic symptom of this binding. Causes, in order of likelihood:

1. **Wrong negotiation bits** — `NEGO` must be clear on the very first record and set on every
   later one.
2. **An unsealed post-handshake message** — sealing is mandatory, not an optimisation.
3. **Token and ciphertext in the wrong order** — the frame is DATA first, TOKEN second, the
   inverse of what GSS emits.

All three are handled by the library; seeing this against a stock build is worth an issue,
with the probe's exit code and the sequence of requests that led to it.

## Convincing binary noise instead of XML

`RESP_XPRESS` got set somewhere and the server compressed its response. This client has no
decompressor, and compressed output looks like a successful read of garbage rather than like
an error. The library never sets that bit.

## An empty rowset where rows were expected

An empty rowset means "nothing visible to this account" — a valid answer, distinct from
`AuthorizationError`. Check the account's permissions on the database and the model.

If the response was not XML at all, you get `ProtocolError` instead, not an empty rowset. That
distinction is deliberate: the likeliest cipher-layer failure produces exactly that
indistinguishable emptiness.

## `NegotiationError`

The server declined clear-text XML. This is the one outcome the design is not built for — it
means [MS-BINXML] would be required for that server, which is a scope change rather than a
configuration problem. Please open an issue with the server version and edition.

## A query times out

Every wait is bounded by the session timeout and there is no way to disable it. Raise it on
the session:

```python
connect("ssas.example.com", 2383, credential, timeout=300.0)
```

## Nothing useful in the error message

That is partly by design: no host, address, account, principal, realm, machine name or SID
survives into an error. The server's own text is in `exc.detail`, scrubbed and truncated to
300 characters.

```python
except SsasError as exc:
    print(type(exc).__name__, exc.message, exc.detail, sep=" | ")
```

If `detail` is empty, the server sent no fault text — the failure was below the SOAP layer.
