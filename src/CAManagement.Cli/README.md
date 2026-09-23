# CAManagement.Cli (`caconsole`)

PKCS#11 and X.509 from the command line, against **any** PKCS#11 module
(SoftHSM2, YubiKey, …) — no vendor tooling required.

```sh
dotnet tool install --global HebelConsulting.CAManagement.Cli
caconsole list-slots
```

- **Token administration** — `list-slots`, `init-token`, `set-pin`, `wipe-token`
  (re-initialise a token in place: destroy every object on it and relabel it).
- **CA lifecycle** — `init-ca`, `issue`, `revoke`, `gen-crl`, `ocsp-respond`,
  with the CA key generated on, and never leaving, the token.
- **Inspection** — `asn` renders a certificate, CSR, CRL, key, PKCS#12, CMS or
  OCSP message as an annotated ASN.1 tree.
- **Apple devices** — `mobileconfig` builds a `.mobileconfig` profile from a
  PKCS#12 identity and/or root certificates.
- **Signing** — `sign` / `verify` with a token key, multi-part for data of any
  size.

## Platforms

This package targets `net10.0` and is correct on **Linux and macOS**.

It is deliberately **not** the Windows build. Windows PKCS#11 modules use LLP64,
where `CK_ULONG` is 4 bytes rather than 8, so the correct Windows binary is built
from the `net10.0-windows` target — and `PackAsTool` cannot carry a
platform-specific target framework (NETSDK1146). On Windows, use the
self-contained `win-x64` binary from the repository's `scripts/publish.sh`
instead of this tool package.

Part of [CAManagement](https://github.com/HebelConsulting/CAManagement).
