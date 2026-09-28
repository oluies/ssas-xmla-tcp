---
title: NTLM
sidebar_position: 2
---

# NTLM

NTLM is the mechanism this library is **verified on**: `Discover`, catalog listing and DAX
execution all complete against a live SQL Server 2022 Analysis Services instance over NTLM, on
both a tabular and a multidimensional named instance.

```python
from ssas_xmla import Credential, connect

with connect(
    "ssas.example.com",
    2383,
    Credential(mechanism="ntlm", principal="DOMAIN\\reader"),
    password="...",          # standalone servers only; see below
) as session:
    print(len(session.catalogs()), "catalogs")
```

## Domain-joined vs standalone

**Domain-joined**, with an ambient identity available to the security layer — leave `principal`
and `password` unset and the credential cache is used:

```python
connect("ssas.example.com", 2383, Credential(mechanism="ntlm"))
```

**Standalone (workgroup)**, where NTLM has no ambient identity to draw on — supply the
principal and the password:

```python
import os

connect(
    "ssas.example.com",
    2383,
    Credential(mechanism="ntlm", principal="SSAS\\reader"),
    password=os.environ["SSAS_PASSWORD"],
)
```

The password reaches the security layer directly. It is never stored on the `Credential`, on
the `Session`, or anywhere a `repr()` or a log line can reach it.

For the probe, the password comes from `$SSAS_PASSWORD` and **only** from there — never from
argv, which is visible in the process list to every other user on the machine.

## The SPN is ignored

NTLM does not match a target service, so the SPN this library requests has no effect on an
NTLM session. `--instance`, `--use-port` and `--spn` change nothing here. That is worth
knowing because it inverts a common diagnosis: an NTLM authentication failure is about the
**account and the password**, never about SPN registration.

## Why the terminal response is still checked

For NTLM the client security context reports completion the moment it emits its last token.
A handshake loop that returns at that point never looks at the server's reply — so a "Logon
failure" carried in that final `AuthenticateResponse` is dropped silently, the session reaches
`AUTHENTICATED`, and the error resurfaces later, mis-attributed to whatever request ran next.

This client fault-checks **every** authenticate response, including the terminal one, and
raises `AuthenticationError` for a fault during the handshake rather than `ServerError`.

## Framing specifics

Two NTLM numbers show up in [the sealed frame](../protocol/sealing.md), and neither is
hardcoded as a constant of the protocol:

- **`tokenSize` is 16** for NTLM. The frame writes `len(token)` and reads the declared size,
  so a mechanism with a larger trailer works unchanged.
- **The chunk size is 2888**, which is NTLM's `cbMaxToken` — the reference client reuses that
  value as its data chunk size. Smaller chunks are always valid, so 2888 stays correct for
  other mechanisms too; it simply will not byte-match their captures.

NTLM reports **zero padding**, which is why it can be framed at all. See
[Kerberos](./kerberos.md#padding-is-the-one-thing-that-cannot-be-framed).
