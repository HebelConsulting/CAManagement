# CAManagement

A .NET 10 toolkit for running a certificate authority whose signing keys never
leave a hardware security module. It speaks PKCS#11 directly, authors X.509
structures itself (no OpenSSL runtime dependency), and ships a single-file
command-line tool, `caconsole`.

Built and maintained by **Hebel Consulting GmbH**. Licensed under Apache-2.0.

Status: 157 tests, green on Linux (CI), Windows (LLP64), and macOS.

---

## Summary

Most CA tooling either wraps OpenSSL or trusts a key sitting in a file. This
project takes a stricter line: the private key lives in a token (SoftHSM2 for
development, a YubiKey or a real HSM in production), every signature is produced
through the token, and the DER that goes over the wire is built and understood
in-house so its every byte is accounted for.

It is organised as three libraries and a CLI, so you can take only the layer you
need:

| Project | Package id | Purpose |
|---------|-----------|---------|
| `CAManagement.Pkcs11` | `HebelConsulting.CAManagement.Pkcs11` | PKCS#11 v2.40 interop — sessions, key generation, sign/verify, encrypt/decrypt (incl. RSA-OAEP for envelope-encryption unwrap), objects. Configurable module. |
| `CAManagement.X509` | `HebelConsulting.CAManagement.X509` | X.509/DER authoring on `System.Formats.Asn1`: certificates, CSRs, CRLs, OCSP, chain validation, and a certutil-style analyzer. No PKCS#11 dependency. |
| `CAManagement.Pkcs11.Signing` | `HebelConsulting.CAManagement.Pkcs11.Signing` | The adapter that lets `CAManagement.X509` sign with a token key. |
| `CAManagement.Cli` | — | `caconsole`, the operator's tool. |

The two layers meet at one small seam, `ICertificateSigner`. Give the X.509
library an HSM-backed signer and it issues from a token; give it a software key
and it issues from memory. Nothing above the seam knows the difference.

### Design principles

- **The key stays in the token.** The library never sees private key material;
  it hands to-be-signed bytes to the token and takes back a signature.
- **We own the bytes.** X.509/CSR/CRL/OCSP structures are authored field by
  field. The .NET and OpenSSL stacks are used in the *tests* as independent
  referees, never at runtime.
- **Portable by construction.** `CK_ULONG` width and struct packing differ
  between Unix (LP64) and Windows (LLP64); both are handled behind one switch,
  verified against real SoftHSM2 on both.
- **Honest about scope.** Where a token or a platform cannot do something, the
  tool says so plainly rather than pretending. See *Caveats* below.

---

## Requirements

- .NET 10 SDK.
- A PKCS#11 module. For development, [SoftHSM2](https://www.opendnssec.org/softhsm/):
  - macOS: `brew install softhsm`
  - Debian/Ubuntu: `apt-get install softhsm2`
  - Windows: the [Disig SoftHSM2 build](https://github.com/disig/SoftHSM2-for-Windows).

`caconsole` finds the module at your platform's default SoftHSM2 location; point
it elsewhere (a YubiKey PKCS#11 library, a vendor HSM) with `--module`.

---

## Manual

`caconsole` is a self-contained binary — no runtime install required on the
target. Build one with `scripts/publish.sh` (produces `dist/<rid>/caconsole`
for `osx-arm64`, `osx-x64`, `linux-x64`, `win-x64`), or run from source with
`dotnet run --project src/CAManagement.Cli --`.

### Connecting to the token

Every command that touches the HSM shares these options:

| Option | Meaning | Default |
|--------|---------|---------|
| `--module <PATH>` | PKCS#11 module to load | platform's SoftHSM2 location |
| `--token-label <LABEL>` | which token to use | first slot with a token present |
| `--slot <ID>` | explicit slot id | — (overrides `--token-label`) |
| `--pin <PIN>` | user PIN | required (no interactive prompt) |

> **PIN handling.** `--pin` is mandatory and is read from the command line. A
> command line is visible to other processes and lands in shell history; supply
> the PIN from a controlled environment, and rotate it if it may have leaked.

### Commands

| Command | Does |
|---------|------|
| `info` | Load the module, print the Cryptoki version and open a session. |
| `list-slots` | List slots, tokens and supported-mechanism counts (like `softhsm2-util --show-slots`). |
| `init-token` | Initialise a token — set the SO PIN, label and user PIN (like `softhsm2-util --init-token`). |
| `set-pin` | Change the token user PIN. |
| `asn <file>` | Analyse a certificate, CSR, CRL, key, PKCS#12, CMS or OCSP message as an annotated tree. |
| `init-ca` | Generate a CA key pair on the token and write a self-signed root. |
| `issue` | Issue a certificate from a PKCS#10 request, signed by the token key. |
| `revoke` | Record a revocation in the CA state. |
| `gen-crl` | Sign a CRL from the CA state. |
| `ocsp-respond` | Answer OCSP requests (file mode or an HTTP responder). |
| `sign` / `verify` | Sign or verify a file with a token key, using multi-part signing for data of any size. |

### Token administration (a softhsm2-util stand-in)

`list-slots`, `init-token` and `set-pin` cover softhsm2-util's day-to-day jobs
through the standard PKCS#11 calls, against **any** module:

```sh
caconsole list-slots
caconsole init-token --free --label ca --so-pin 123456 --pin 1234
caconsole set-pin --token-label ca --pin 1234 --new-pin 5678
```

(`--free` picks the first uninitialised slot, or use `--slot <id>`.) Key/cert
*import* is `C_CreateObject` (used by the CA commands); token *deletion* is a
SoftHSM-specific extension, not a standard PKCS#11 function, so it is out of
scope here.

### A complete walk-through

Provision a development token (once):

```sh
softhsm2-util --init-token --free --label ca --so-pin 123456 --pin 1234
```

**1 — Stand up the CA.** Generates the key on the token; only the self-signed
certificate comes out.

```sh
caconsole init-ca --token-label ca --pin 1234 \
    --label root --key-type ec \
    --subject "/C=CH/O=Hebel Consulting GmbH/CN=Hebel Consulting Root CA" \
    --years 10 --out ca.crt
```

`--key-type` is `ec` (P-256, default) or `rsa` (2048). `--subject` accepts the
OpenSSL slash form or the comma form, and per-component string-type annotations,
e.g. `CN=[PrintableString]www.example.org`.

**2 — Issue from a request.** The requester's proof-of-possession signature is
verified before anything is signed; only the Subject Alternative Name extension
is honoured from the request.

```sh
caconsole issue --token-label ca --pin 1234 \
    --ca-label root --ca-cert ca.crt \
    --csr server.csr --days 365 --out server.crt
```

**3 — Revoke and publish a CRL.**

```sh
caconsole revoke  --serial 0A1B2C --reason KeyCompromise
caconsole gen-crl --token-label ca --pin 1234 \
    --ca-label root --ca-cert ca.crt --days 7 --out ca.crl
```

Revocation reasons: `Unspecified`, `KeyCompromise`, `CaCompromise`,
`AffiliationChanged`, `Superseded`, `CessationOfOperation`, `CertificateHold`,
`RemoveFromCrl`, `PrivilegeWithdrawn`, `AaCompromise`.

**4 — Answer OCSP.** One-shot, against a DER request:

```sh
caconsole ocsp-respond --token-label ca --pin 1234 \
    --ca-label root --ca-cert ca.crt \
    --reqin request.der --respout response.der
```

…or as an HTTP responder (RFC 6960 POST and GET):

```sh
caconsole ocsp-respond --token-label ca --pin 1234 \
    --ca-label root --ca-cert ca.crt \
    --listen http://127.0.0.1:8080/ --validity-hours 24
```

A serial recorded by `revoke` reports `revoked`; any other serial of this CA
reports `good` (issuance is not tracked); a foreign issuer reports `unknown`.

### Where CA state lives

`revoke`, `gen-crl` and `ocsp-respond` share the CRL number and revocation list
through `--state`:

- `--state ca-state.json` (default) — a JSON file next to you.
- `--state token` — a data object on the HSM, so the bookkeeping travels with
  the key and is reachable only after login. This mode also needs `--ca-label`
  and `--pin`.

### Inspecting anything — `asn`

`asn` reads PEM or DER and renders the structure on the left with a plain-English
field explanation on the right. It recognises certificates, PKCS#10 requests,
CRLs, `SubjectPublicKeyInfo`, PKCS#8 / PKCS#1 / SEC1 private keys, PKCS#12
containers, CMS/PKCS#7, OCSP requests and responses, and OpenSSH keys.

```sh
caconsole asn server.crt
caconsole asn /etc/ssl/cert.pem --index 42   # pick one cert from a bundle
caconsole asn ~/.ssh/id_ed25519              # OpenSSH keys are decoded, not just rejected
```

Encrypted material (a PKCS#12 bag, an OpenSSH private key with a passphrase) is
shown as structure with its KDF parameters; secrets stay opaque.

---

## Using the libraries

The packages are published to **nuget.org** and **GitHub Packages** on every push to `main` that bumps the
shared `<Version>` in `src/Directory.Build.props`:

```xml
<PackageReference Include="HebelConsulting.CAManagement.Pkcs11" Version="0.2.0" />
```

nuget.org is the default source everywhere, so that line alone restores with **no credentials**. The
GitHub Packages feed remains for consumers already inside the GitHub token perimeter:

```xml
<add key="hebelconsulting" value="https://nuget.pkg.github.com/HebelConsulting/index.json" />
```

**GitHub Packages requires authentication even to read** — this repository being public does not make its
feed anonymous (a public package's `.nupkg` answers 401 without a token; verified). A consumer there
authenticates with any token carrying `read:packages` (CI uses its own `GITHUB_TOKEN`; locally,
`NuGetPackageSourceCredentials_hebelconsulting="Username=<user>;Password=<token>"` — the exact
environment-variable spelling matters, a wrong form is a bare 401). If you only need to restore, use
nuget.org and skip all of that.

Issue a certificate with a software key (swap `ICertificateSigner` for the
PKCS#11 one to sign on a token — prefer `Pkcs11CertificateSigner.ForKey(session,
privateKeyHandle)`, which derives the algorithm from the key's own
`CKA_KEY_TYPE` and cannot mismatch; the explicit-algorithm constructor validates
the key type up front and throws, because SoftHSM answers a mechanism/key
mismatch by crashing the process rather than returning an error):

```csharp
using CAManagement.X509;

var subject = DistinguishedName.Parse("/C=CH/O=Hebel Consulting GmbH/CN=Example");

var der = new CertificateBuilder
{
    Subject              = subject,
    SubjectPublicKeyInfo = subjectPublicKeyInfo,   // from the token or a software key
    NotBefore            = DateTimeOffset.UtcNow,
    NotAfter             = DateTimeOffset.UtcNow.AddYears(1),
    Extensions =
    [
        CertificateExtensions.BasicConstraints(isCa: false),
        CertificateExtensions.KeyUsage(KeyUsages.DigitalSignature),
    ],
}.Sign(issuer: subject, signer);        // signer : ICertificateSigner
```

Packages are `net10.0` (plus `net10.0-windows` for the PKCS#11 layers). A
**Windows consumer must target `net10.0-windows`** to get the LLP64 assembly —
a plain `net10.0` app on Windows would pick the LP64 build and corrupt every
`CK_ULONG`.

---

## Building, testing, packaging

```sh
dotnet build  CAManagement.sln -c Release
dotnet test   CAManagement.sln              # 157 tests; integration tests need SoftHSM2
scripts/publish.sh                          # self-contained caconsole per platform
scripts/pack.sh                             # the three NuGet packages
```

CI (`.github/workflows/ci.yml`) builds, tests and packs on every push and PR
against a real SoftHSM2 on Linux. `windows-verify.yml` runs the full suite on a
real Windows runner against the LLP64 build; it is manual, because Windows
minutes are billed at a premium.

---

## Caveats & scope

- **PKCS#11 2.40.** The version SoftHSM2 implements. 3.0 is additive and can be
  layered on later without reworking what exists.
- **`CKM_ECDSA_SHA256` is not in every SoftHSM build** (present in Homebrew
  2.7.0, absent in Ubuntu 2.6.1 and the Disig Windows 2.5.0 package). EC-signing
  integration tests skip where the mechanism is missing; the CLI end-to-end test
  uses an RSA CA so it runs everywhere. An RSA or EC CA both work against a token
  that implements the mechanism.
- **CRL numbers need a persisted counter for strict monotonicity.** RFC 5280
  requires the CRL number to strictly increase per issuer/scope. The CLI keeps
  a persisted counter (`--state`, file or on-token) and is safe. `CrlBuilder`'s
  *default* — seconds since the Unix epoch — is a convenience for callers that
  don't supply one; it is only monotonic while you issue **at most one CRL per
  second** and the **clock never moves backward** (an NTP step-back or VM
  snapshot restore could otherwise produce a lower number, which relying parties
  may treat as stale). For anything beyond one CRL per second, pass an explicit
  `CrlNumber`.
- **`asn` decodes; it does not decrypt.** Password-protected containers are
  shown as structure plus KDF parameters, not opened.
- **`CertificatePolicies`** supports the policy OID with optional CPS-URI and
  user-notice text; `noticeRef` is intentionally unsupported.
- **Not a policy engine.** The library issues exactly what you ask it to. Name
  constraints, path-length enforcement beyond what you set, and issuance policy
  are the caller's responsibility.

---

© Hebel Consulting GmbH. Apache-2.0. See [`LICENSE`](LICENSE).
