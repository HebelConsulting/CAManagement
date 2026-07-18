# CAManagement — Specification (v1)

A .NET 10 library (with console app + tests) that wraps a PKCS#11 module via
managed interop, targeting **SoftHSM2** first and other modules (e.g. YubiKey)
later. A separate ASN.1/DER CA-management library will be layered on top at a
later stage.

## Source of truth
- **PKCS#11 definitions:** [oasis-tcs/pkcs11](https://github.com/oasis-tcs/pkcs11),
  `published/2-40/` headers (`pkcs11t.h`, `pkcs11f.h`). **Pinned to v2.40.**
- **Style reference only (we do *not* like its style):**
  [Pkcs11Interop/Pkcs11Interop](https://github.com/Pkcs11Interop/Pkcs11Interop).

## Platforms
- Primary: **Linux, macOS**. Windows later.
- Local dev/test HSM: **SoftHSM2 2.7.0** (Homebrew),
  module `/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so`.

## Decisions (agreed)

| # | Topic | Decision |
|---|-------|----------|
| 1 | Invocation | Resolve **only** `C_GetFunctionList`; call every other function through the `CK_FUNCTION_LIST` pointers via **delegates** (`Marshal.GetDelegateForFunctionPointer`). Per-function `[LibraryImport]` blocks are removed. |
| 2 | Module loading | `NativeLibrary.Load(options.ModulePath)`. `ModulePath` has a **per-OS default**, overridable via config. |
| 3 | PKCS#11 version | **Pinned to 2.40** (matches SoftHSM2 2.7.0, which has no 3.0 `C_GetInterface`). 3.0 is additive → can be layered on later with zero rework. |
| 4 | Windows portability | Centralize `NativeULong` (8 bytes on LP64 Unix, 4 on LLP64 Windows) and struct `Pack` behind **one platform switch** now, even though Windows isn't implemented yet. |
| 5 | Configuration | `IOptions<Pkcs11Options>` + `appsettings.json` (`services.Configure<Pkcs11Options>(config.GetSection("Pkcs11"))`). |
| 6 | Error handling | Central `CheckRv(rv, op, params allowedExtra)` throws a custom **`Pkcs11Exception(CK_RV, op)`** on anything but `CKR_OK`. Carve-out: length-probe calls may allow `CKR_BUFFER_TOO_SMALL`. |
| 7 | Lifecycle | Nested `IDisposable` ownership (below). Login via a **`LoginScope`** (`using` → `C_Logout`). |
| 8 | Threading | `C_Initialize` with **`CKF_OS_LOCKING_OK`** (`Pkcs11Options.UseOsLocking = true`). |
| 9 | Slot selection | Default by **`TokenLabel`**; `SlotId` as explicit override. |
| 10 | Test keys | Bind **`C_GenerateKeyPair`**; the integration fixture generates its own key. |
| 11 | Target framework | **`net10.0`** across all three projects. |

## Ownership tree

```
Pkcs11Library : IDisposable
  ctor: NativeLibrary.Load(ModulePath)
        -> GetExport("C_GetFunctionList") -> delegate -> call
        -> Marshal.PtrToStructure<CK_FUNCTION_LIST>
        -> GetDelegateForFunctionPointer for each IntPtr (cached)
        -> C_Initialize(CKF_OS_LOCKING_OK)
  Dispose: C_Finalize -> NativeLibrary.Free
    |
    +-- Pkcs11Session : IDisposable   (library.OpenSession(flags))
    |     resolves slot via TokenLabel/SlotId; owns session handle
    |     Dispose: C_CloseSession
    |       |
    |       +-- LoginScope : IDisposable   (session.Login(CKU_USER, pin))
    |       |     Dispose: C_Logout
    |       |
    |       +-- operations: FindObjects / GenerateKeyPair / Sign / Verify
    |             +-- NativeAllocationScope : IDisposable
    |                   wraps AllocHGlobal for attribute templates &
    |                   mechanism params; Dispose frees all
```

## Pkcs11Options

```csharp
public sealed class Pkcs11Options
{
    public string  ModulePath   { get; set; } = <per-OS default>; // override in appsettings
    public string? TokenLabel   { get; set; }   // preferred slot selection
    public ulong?  SlotId        { get; set; }  // explicit override
    public string? UserPin       { get; set; }  // dev-only; secret handling TBD
    public bool    UseOsLocking  { get; set; } = true; // CKF_OS_LOCKING_OK
}
```

## Testing (local-only for now)
- **Unit** (no HSM): `NativeAllocationScope` attribute encoding, inline-array
  string trimming, the `Mechanisms.KeyTypeFor` switch, options defaulting.
- **Integration** (`SoftHsmFixture`): writes a throwaway `softhsm2.conf` to a temp
  dir, points `SOFTHSM2_CONF` at it, `softhsm2-util --init-token --free`, generates
  an RSA keypair, runs Initialize/OpenSession/Login/GenerateKeyPair/Sign/Verify
  round-trips (by explicit key handle), tears the temp dir down.

## Operational learnings (verified against SoftHSM2 2.7.0)
- **`SOFTHSM2_CONF` must be set via native `setenv`.** On macOS, .NET's
  `Environment.SetEnvironmentVariable` does NOT reach native `getenv`, so the
  module ignores a managed-only setting and falls back to the default config.
  The fixture P/Invokes libc `setenv`. Real deployments should set it in the
  process environment before launch.
- **SoftHSM 2.7.0 advertises a 3.02 function-list header** while implementing
  2.40 semantics. We bind the 2.40-shaped `CK_FUNCTION_LIST` (ends at
  `C_WaitForSlotEvent`); the version field is informational only.
- **Struct packing**: `CK_SLOT_INFO`/`CK_C_INITIALIZE_ARGS` had `Pack=1`, which
  drops trailing padding and under-sizes the marshalled buffer on Unix LP64.
  Standardized on natural alignment (SPEC #4).

## DataStructures completeness (verified against `published/2-40-errata-1` headers)
- **All constants complete**: every `#define` in pkcs11t.h (CKR/CKA/CKM/CKK/CKO/
  CKC/CKU/CKS/CKD/CKG/CKZ/CKP/CKH/CKN/CKF/CK_*) has a C# representation.
- **Structs**: all operational structs present (`CK_INFO`, `CK_SESSION_INFO`,
  `CK_MECHANISM_INFO`, `CK_DATE`, token/slot info, function list) plus the
  crypto-relevant mechanism params (`CK_RSA_PKCS_PSS_PARAMS`,
  `CK_RSA_PKCS_OAEP_PARAMS`, `CK_ECDH1_DERIVE_PARAMS`).
- **Deliberately omitted — leave until a concrete need shows up** (decision
  2026-07-17): the remaining 53 mechanism-param structs. Mostly legacy protocol
  baggage (SSL3/TLS12/WTLS key material, OTP, RC2/RC5/DES/SKIPJACK, GOST/SEED/
  CAMELLIA/ARIA, PBE/PBKD2, X9.42/ECMQV/ECDH2, KEA, KIP, CMS_SIG,
  KEY_WRAP_SET_OAEP) plus a few modern-but-out-of-scope ones. Do NOT add
  speculatively. Plausible first additions if a need arises:
  `CK_AES_GCM_PARAMS` (HSM symmetric encryption), AES key-wrap params /
  `CK_RSA_AES_KEY_WRAP_PARAMS` (key backup/escrow).
- `StructLayoutTests` locks every marshalled struct to its LP64 size; the
  Windows port must revisit these together with `NativeULong`/packing (SPEC #4).

## Console CLI
- **Spectre.Console.Cli** (replaced CommandLineParser), wired to DI via a
  `TypeRegistrar`/`TypeResolver` bridge. First command: `caconsole info`.
- `CAConsole.csproj` targets `RuntimeIdentifier=osx-arm64` so it can load the
  arm64 `libsofthsm2.so`. `caconsole info` needs an initialized token in the
  active `SOFTHSM2_CONF`; the default config reports `CKR_TOKEN_NOT_RECOGNIZED`.

## CLI configuration (changed 2026-07-18)
The CLI no longer reads `appsettings.json` or environment variables; all HSM
parameters are CLI options with educated defaults (`HsmSettings`): `--module`
(default: the platform's SoftHSM2 location), `--token-label` (default: first
slot with a token present), `--slot` (overrides the label), `--pin` (default:
interactive secret prompt). Decision #5 (`IOptions<Pkcs11Options>` binding)
still holds for the *library* — hosts that want config files keep `AddPkcs11`.

## NuGet packaging (added 2026-07-18)
- `scripts/pack.sh` packs the three libraries into `dist/nuget/`.
  **PackageIds carry the `HebelConsulting.` prefix** (reservable on nuget.org)
  while assemblies/namespaces stay `CAManagement.*`; project references map to
  prefixed package dependencies automatically.
- Shared metadata in `src/Directory.Build.props`: single `Version` (0.1.0),
  Apache-2.0 expression, repository URL, per-package README, embedded debug
  info (no symbol packages). Packing is opt-in per library; CLI and tests are
  not packable.
- Verified by consuming from a scratch project via a local feed: transitive
  dependency resolution plus real API usage (DN parse, issuance, validation).
- Publishing to nuget.org (API key, prefix reservation, CI) is a manual step
  left to the maintainer.

## CA state on token (added 2026-07-18, closes the D5 deferral)
- `--state token` on revoke/gen-crl/ocsp-respond keeps the CA state (CRL
  number + revocations, same JSON as the file store) as a CKO_DATA object
  labelled `ca-state:<ca-label>` — it lives with the CA key and is only
  reachable after login. revoke gains `--ca-label`/`--pin` for this mode.
- SoftHSM quirk (verified): in-place `C_SetAttributeValue` on a data object's
  CKA_VALUE returns CKR_ATTRIBUTE_READ_ONLY, but CKA_LABEL updates work.
  `TokenCaStateStore` therefore saves via staged rename (create `.new` →
  destroy old → relabel), and Load self-heals a crash between the last two
  steps by adopting the staged object.
- The `C_SetAttributeValue` binding exists in CAManagement.Pkcs11 regardless
  (label updates are its verified use).

## Publishing (added 2026-07-17)
- `scripts/publish.sh` builds self-contained single-file `caconsole` binaries
  for **osx-arm64, osx-x64, linux-x64** into `dist/<rid>/` (single binary;
  debug info embedded). No trimming (reflection-based DI)
  and no ReadyToRun (keeps cross-OS publishing from macOS possible).
- `InvariantGlobalization=true` on the CLI: self-contained does NOT bundle
  native OS deps — without it the Linux binary fail-fasts on missing libicu
  (verified in a bare Debian container). Invariant formatting is also the
  right behavior for a crypto CLI.
- Verified: arm64 natively (real workload), osx-x64 under Rosetta, linux-x64
  in a linux/amd64 Debian container (help + analyzer workload).

## Project naming (renamed 2026-07-17)
Projects/namespaces were renamed to dotted product names — earlier sections may
use the old names:
`Pkcs11Interop` → `CAManagement.Pkcs11` (removed the collision with the
third-party library of the same name), `CertificateAuthority` →
`CAManagement.X509` (frees the type name; content is X.509/DER authoring),
`Pkcs11Signing` → `CAManagement.Pkcs11.Signing`, `CAConsole` →
`CAManagement.Cli` (not `.Console` — a `Console` namespace segment hijacks
unqualified `System.Console` references; binary remains `caconsole`),
`CAManagementTests` → `CAManagement.Tests`. Longer NuGet `PackageId`s (e.g.
`HebelConsulting.*`) can be layered on at packaging time without renaming again.

## Distinguished names (added 2026-07-17)
- `DistinguishedName.Parse` accepts the OpenSSL slash form (`/C=CH/O=…/CN=…`,
  `\/`-escaping) and the comma form; values may carry a string-type annotation
  prefix (`CN=[PrintableString]name`, hyphenated spellings accepted). The
  bracket-prefix syntax was chosen over a `value@Type` suffix because `@`
  legitimately occurs in emailAddress values.
- Decoded components remember their original string types, so
  Decode→Encode is byte-faithful for foreign encodings (e.g. framework/openssl
  PrintableString CNs) — required when extracting a CA subject as CRL issuer.
- `X509Names.SubjectOf`/`IssuerOf` extract names from certificate/CSR/CRL
  (PEM or DER) without signature verification; the console's issue/gen-crl use
  them.

## Conventions
- String **interpolation** over `+` concatenation.
- Prefer **switch expressions** (lambda notation).
- Clean code; tests written alongside implementation.
- **No architectural decisions without prior consent.**

## CA library design (agreed 2026-07-17)

| # | Topic | Decision |
|---|-------|----------|
| D1 | Encoding primitive | **`System.Formats.Asn1`** (`AsnWriter`/`AsnReader`, DER). We author every structure; we do not re-implement TLV. |
| D2 | Structure modeling | **Own DER models** (`TbsCertificate`, `DistinguishedName`, `AlgorithmIdentifier`, SPKI, extensions). Framework X.509 types are used in *tests only* as an independent verifier. |
| D3 | Layout | **Split**: `CAManagement.X509` (pure, no PKCS#11 reference, exposes `ICertificateSigner`) + `CAManagement.Pkcs11.Signing` adapter (references both; owns the ECDSA raw r&#124;&#124;s → DER conversion). |
| D4 | Scope | v1 ✅ + v2 ✅ + v3 ✅ (2026-07-17): Name/AlgId/OIDs/SPKI/TBS + core extensions, self-signed CA + issue cert, PKCS#10 CSR intake (PoP verified in Decode), CRL building, OCSP (request decode incl. nonce, signed BasicOCSPResponse builder, error responses), chain helpers (`CertificateValidation` — a deliberate thin wrapper over `X509Chain` with custom root trust; path validation is framework territory, same reasoning as D1 for TLV — and `CertificateBundle` for PEM bundles + own-DER certs-only PKCS#7). Note: LibreSSL 3.3.6's `ocsp` client fails nonce checks even against its own responder — nonce echo is asserted byte-exactly in our tests instead. |
| D5 | CA state | v1 **stateless** (caller supplies serial/validity; random 16-byte serials by default). State design deferred to the CRL phase. |
| D6 | Testing | Unit: DER golden vectors, `AsnReader` round trips, software-key signing. Integration: HSM-key CA issues certs validated by `X509Certificate2`/`X509Chain`; CRLs cross-checked by framework `Load`, manual signature verify, and openssl. CLI: `ConsoleEndToEndTests` builds the caconsole binary and drives init-ca → issue → revoke → gen-crl → asn as child processes against a throwaway token. |

## Future
- Windows support (activates the #4 platform switches).
- Optional PKCS#11 3.0 layer via `C_GetInterface` when a 3.0 module is added.
