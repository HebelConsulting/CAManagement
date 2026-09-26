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
- **A mechanism/key-type mismatch is a PROCESS CRASH, not a CKR error.** Asking
  SoftHSM to `C_Sign` with an RSA mechanism against an EC key segfaults inside
  the module (`OSSLRSA::signFinal → RSA_sign → RSA_size(NULL)`) — exit 139,
  zero output, only the OS crash report to read (verified 2026-09-22 via a
  consumer that hardcoded `Sha256WithRsa` against an EC CA; issue #9).
  `Pkcs11CertificateSigner` therefore validates `CKA_KEY_TYPE` against the
  requested algorithm at construction and throws a message naming both sides,
  and `Pkcs11CertificateSigner.ForKey` derives the algorithm from the key so a
  "sign with this key" caller cannot mismatch at all (the CLI's `LoadCaKey`
  now goes through it). Covered by `SignerKeyTypeTests`.

## Enumerating a token's objects (added 2026-09-26, version 0.7.0)

`FindObjects` had two overloads, both **requiring a discriminator** — a key type, or an exact label. That serves
a caller who already knows what it is looking for, and it cannot serve one that has to **enumerate**: *"which
certificates does this token carry?"* has no label to search by.

`FindObjects(CK_OBJECT_CLASS objectClass)` matches on class and `CKA_TOKEN` alone.

**Why the label overload is not enough, stated because it looks sufficient.** A PIV card has four key slots and
may carry a certificate in each; OpenSC maps them to fixed labels (`Certificate for Key Management` and its
siblings), and a non-PIV token may use any labels at all. A consumer narrowing by label therefore hard-codes one
vendor's slot naming and sees **nothing** on a token that names things differently — a silent empty result, not
an error. A user may also have **two tokens plugged in**, so the unit to walk is `GetSlotList(tokenPresent: true)`
and then this call per slot.

Verified on SoftHSM2 (three certificates under unrelated labels, found without any of them, with the class still
discriminating against the keys sharing the token) and on a **YubiKey 5C Nano** over OpenSC, where it returns the
PIV Key Management certificate with no label supplied.

**Two measurements worth carrying, both about what this call CANNOT tell you.** Certificates are public objects,
so enumerating them needs **no login** — but `CKO_PRIVATE_KEY` objects are invisible until `C_Login`, so
*"does a key for this certificate live on this token?"* cannot be answered before a PIN is collected. And the
YubiKey's own Key Management certificate, issued by `caconsole`, states `keyUsage = DigitalSignature` only —
while demonstrably decrypting a real CMS envelope, because neither `EnvelopedCms` nor the token enforces
`keyUsage`. A consumer that refuses a certificate on `keyUsage` grounds would therefore refuse one that works.

## Token labels must be unique (Pkcs11 package)

- **A label that resolves to MORE THAN ONE token is refused, not guessed between.** `ResolveSlot` used to
  return the first match; a consumer whose provisioning created a second token with the same label then
  opened a session on keys that merely looked right — for envelope encryption that means wrapping against
  one token and failing to unwrap against another, i.e. silently unreadable data with every call
  returning success. Found in the wild 2026-09-23 (SimplArchiveEncryption: a "does the token exist?" test
  anchored immediately after the label never matched, because **SoftHSM pads labels with trailing
  spaces**, so every restart initialized another token — three ended up sharing one label). Covered by
  `AmbiguousTokenLabelTests`; pass an explicit `SlotId` when duplicates are legitimate.

## MobileConfigProfile (X509 package)

- **The `.mobileconfig` builder lives in `CAManagement.X509`, not in a consumer** (added with the
  `caconsole mobileconfig` verb): the SimplArchiveEncryption identity tool carried the first hand-rolled
  copy of the plist, the CLI verb would have been the second — one implementation, both consume it.
  Payload types: `com.apple.security.pkcs12` (identity; the password is EMBEDDED so installs do not
  prompt — the documented hand-delivery trade) and `com.apple.security.root`. Verified against an
  independent plist parser (python plistlib) in the smoke run and `MobileConfigProfileTests` (XML
  round-trip incl. escaping of hostile display names).

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

## caconsole as a .NET tool (added 2026-09-23)
- The CLI ships as **`HebelConsulting.CAManagement.Cli`**, a `PackAsTool` package
  installed with `dotnet tool install --global`, published by the same workflow
  and the same shared `<Version>` as the three libraries.
- **Why:** a consumer needs the tool without building this repository. The first
  is the encryption sibling's container image, which must administer its own
  PKCS#11 token; its ADR 0003 is "consume, never copy", and a source dependency
  across repositories would be exactly the copy.
- **net10.0 only, deliberately.** `PackAsTool` rejects a platform-specific TFM
  (NETSDK1146), and keeping `net10.0-windows` in the package fails NU5128 — a
  dependency group with no lib behind it. Packing is therefore gated behind
  `-p:PackTool=true` (scripts/pack.sh), which switches the CLI to that single
  target for the pack pass while normal builds stay multi-targeted.
- **Windows is not served by this package and must not be.** `CK_ULONG` is 4
  bytes there (LLP64, decision #4), so the net10.0 build would make wrong-ABI
  calls against a Windows PKCS#11 module — on a tool that administers tokens.
  Windows keeps the existing channel: the self-contained `win-x64` binary from
  `scripts/publish.sh`, built from `net10.0-windows`. Stated in both READMEs.

## Enrolment: csr + import-cert (added 2026-09-24)
- `csr` builds a PKCS#10 request signed through `ICertificateSigner`, the same seam the CA signs with, so
  the signing key may live on a token. `CertificateSigningRequestBuilder` is its X509-side half — the class
  could previously only `Decode`.
- **Why it was missing matters:** `issue` could sign a request and nothing could produce one, so turning a
  token-resident key into a certificate required the card vendor's tool. That is per-vendor and therefore
  per-customer; PKCS#11 is not.
- `import-cert` stores the issued certificate back on the token. The PKCS#11 layer deliberately does not
  parse certificates, so the CLI supplies the subject DER — taken from the certificate itself, since an
  object findable under a name that is not its own is worse than no object.
- **Tested against the decoder, not against itself.** `Decode` verifies the self-signature and refuses a
  request that does not, so it is an independent oracle; the framework's own `LoadSigningRequest` is a
  second one. `EnrolmentLoopTests` runs the whole loop on a real SoftHSM token.
- **The empty-attributes case is the trap.** `CertificationRequestInfo` requires the `[0] IMPLICIT SET OF
  Attribute` tag even with nothing to say; omitting it yields a structure that encodes happily and fails at
  whatever tries to read it.
- **Out of scope, stated:** key generation and card personalisation (PIV CHUID/CCC, slot choice) are
  card-applet operations rather than PKCS#11 ones, and stay with the card tooling.

## Token wiping (added 2026-09-23)
- `wipe-token` re-initialises a token in place (`C_InitToken`): every object on
  it is destroyed and it takes a new label.
- **Named for what it does.** PKCS#11 has no delete-token operation and the slot
  survives, so calling it `delete-token` would promise something the standard
  cannot deliver. Removing a token *directory* is SoftHSM-specific file surgery
  and stays out of this tool.
- **Addressed by `--slot` only.** The reason to wipe a token is normally that its
  label is ambiguous; resolving by label would pick between the duplicates at
  random, which is the defect, not the cure.
- Guardrails: the existing SO PIN is required (C_InitToken authenticates as SO),
  `--new-label` is mandatory so a wiped token cannot keep colliding under the old
  one, and `--yes` is mandatory because there is no undo.
- Caveat stated at the call site and in the README: the wiped token has **no user
  PIN** afterwards.
- **Trigger.** A deployment accumulated three tokens all labelled `encryption`
  because a provisioning script's existence check never matched (SoftHSM pads the
  label with trailing spaces). The service then resolved the label to a different
  keypair on each restart and minted a fresh KEK, silently orphaning every
  previously wrapped key — with a healthy container and every endpoint answering
  200. Detecting that is issue #12; this verb is the remedy for it.

## Windows port (added 2026-07-19 — realizes decision #4)
- `CAManagement.Pkcs11`, `CAManagement.Pkcs11.Signing` and the CLI multi-target
  **net10.0 (Unix LP64) + net10.0-windows (LLP64)**: the `WINDOWS` symbol flips
  `NativeULong` to `UInt32` and `Pkcs11Layout.Pack` to 1 (Windows' pkcs11.h
  `#pragma pack(1)`), wired into every marshalled struct. A compile-time width
  guard in `Pkcs11Layout` fails the build if alias and platform disagree; a
  `#error` probe verified the symbol fires exactly on the -windows TFM.
  Enum `UL` suffixes were stripped (illegal initializers under a uint backing;
  unsuffixed hex fits both widths); width-dependent reads use `MemoryMarshal`.
  `CAManagement.X509` has no native ABI and stays single-TFM.
- Windows module default: `softhsm2-x64.dll`. `publish.sh` adds **win-x64**
  (`caconsole.exe`, PE32+ verified). NuGet packages carry both TFM assets.
- **Consumer caveat**: a Windows app must target `net10.0-windows` to get the
  LLP64 asset — a plain `net10.0` app on Windows would silently pick the LP64
  assembly and corrupt every CK_ULONG.
- **Runtime-verified on real Windows** (2026-07-19): the `.github/workflows/
  windows-verify.yml` job (manual `workflow_dispatch`) runs the full suite on
  `windows-latest` against the Disig SoftHSM2 portable build, using the
  net10.0-windows (LLP64) assemblies — **157/157 passed** (GH Actions run
  29679052250). This exercises the LLP64 struct sizes (StructLayoutTests
  Windows table), RSA generate/sign/verify interop, object management, CA
  issuance/CRL/OCSP and the console lifecycle end to end.
- Two Windows-specific findings from that run, both handled: (1) the portable
  `softhsm2-util.exe` needs its sibling DLLs on `PATH`; the test harness sets
  it. (2) `CKM_ECDSA_SHA256` is not implemented by every SoftHSM build — absent in
  the Disig Windows 2.5.0 and Ubuntu 2.6.1 packages, present in Homebrew
  2.7.0. EC keygen still succeeds everywhere (proving the `CK_MECHANISM`
  marshalling), while EC-with-hash signing returns `CKR_MECHANISM_INVALID`
  where unimplemented. EC-signing HSM tests self-skip via
  `SoftHsmFixture.SupportsEcdsaSha256()`; the console E2E uses an RSA CA
  (`CKM_SHA256_RSA_PKCS`, universal) on all platforms. This is a token
  feature gap, not an ABI issue.

## Continuous integration (added 2026-07-20)
- `.github/workflows/ci.yml` runs on every push to `main` and every PR:
  `ubuntu-latest` installs SoftHSM2 (symlinking the module to the Linux
  default path), builds Release, runs the full suite (157), packs the three
  NuGet libraries and uploads them as an artifact. Concurrency cancels
  superseded runs.
- `.github/workflows/windows-verify.yml` stays manual (`workflow_dispatch`;
  Windows minutes bill 2x on private repos) and verifies the LLP64 build.
- Coverage split: Linux CI on every change (fast, free-ish), Windows on
  demand, macOS as the local dev loop. All three run the same 157 tests
  green. Integration tests build the console for the host RID, so the E2E is
  OS/arch-agnostic; the CLI csproj no longer pins a RID (publish.sh and the
  E2E pass `-r` explicitly).

## CLI configuration (changed 2026-07-18)
The CLI no longer reads `appsettings.json` or environment variables; all HSM
parameters are CLI options with educated defaults (`HsmSettings`): `--module`
(default: the platform's SoftHSM2 location), `--token-label` (default: first
slot with a token present), `--slot` (overrides the label). `--pin` is
**mandatory** on login commands (`HsmLoginSettings`; no interactive prompt);
`info` needs no PIN and `revoke` requires one only with `--state token`.
Note: Spectre constructs settings via reflection and does not enforce the C#
`required` modifier — the mandatory PIN is enforced by explicit validation.
Decision #5 (`IOptions<Pkcs11Options>` binding)
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
- **Publishing to GitHub Packages is CI-automated** (added 2026-09-21, issue #1):
  `.github/workflows/publish-packages.yml` packs and pushes on every `main` push touching a packable
  library, idempotent via `--skip-duplicate`. The idempotence carries a known trap — library changed but
  version unbumped is a green run that publishes NOTHING — so the workflow probes the feed first and emits a
  prominent warning for exactly that condition; whether a change deserves a bump stays the maintainer's
  call. **nuget.org is a second push in the same workflow** (added 2026-09-21), authenticated by
  **trusted publishing** rather than a stored key: the nuget.org policy ("PushCAManagement", created by
  `monacense`, package owner HebelConsulting, glob `HebelConsulting*`) pins this repository +
  `publish-packages.yml` + the `public` environment, and `NuGet/login` exchanges the run's OIDC token
  for a short-lived push key — its `user:` input names the policy CREATOR, not the package owner
  (giving it the owner is a bare 401, measured on the first attempt).
  No secret exists to rotate or leak; the flip side is that renaming the workflow file or dropping the
  job's `environment: public` breaks the policy match and the exchange fails. Same `--skip-duplicate`
  idempotence on both feeds. nuget.org is the anonymous-read feed — GitHub Packages answers 401 even
  for a public package's `.nupkg` (verified empirically 2026-09-21), so consumers without a GitHub
  token get the packages from nuget.org instead. Reserving the `HebelConsulting.*` prefix on nuget.org
  stays a manual, optional maintainer step.

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
- **CRL number monotonicity (RFC 5280 §5.2.3).** The CRL number MUST strictly
  increase per issuer/scope; this is a *stateful* invariant, so the source of
  truth is the persisted counter above (`state.CrlNumber++`), which the CLI
  always passes explicitly. `CrlBuilder.CrlNumber` *defaults* to
  `(ulong)(UtcNow - UnixEpoch).TotalSeconds` purely as a fallback for callers
  that supply none — and it is only monotonic under two assumptions: at most
  one CRL published per second (else two CRLs collide on the same number) and a
  never-backward clock (an NTP step-back or VM snapshot restore could emit a
  lower number, which relying parties may treat as stale — a
  revoked-looks-valid hazard). Callers needing more than one CRL per second, or
  robustness against clock anomalies, must pass an explicit `CrlNumber` (the CLI
  does). 64-bit `ulong`, so no 2038/overflow concern.

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

## Encrypt/decrypt for envelope encryption (added 2026-09-21, issue #1)

Added for [SimplArchiveEncryption](https://github.com/HebelConsulting/SimplArchiveEncryption), whose only
token-bound operation is unwrapping a small data key with a token-resident private key — bulk crypto never
goes through PKCS#11. This realises the "sanctioned first additions" carve-out in the completeness section:
a concrete need arrived, and exactly what it needs was added.

- **Bound**: `C_EncryptInit` / `C_Encrypt` / `C_DecryptInit` / `C_Decrypt`, reusing the existing
  sign/verify delegate shapes (the C header agrees; no new delegate types). Session surface:
  `Encrypt`/`Decrypt` (parameterless mechanisms) and `EncryptRsaOaep`/`DecryptRsaOaep`, which are the first
  consumers of `CK_RSA_PKCS_OAEP_PARAMS` and of mechanism parameters at all. `NativeAllocationScope` gained
  `Allocate<T>(in T)` for parameter blocks; the scope must outlive the whole init+operate pair.
- **Still deliberately omitted**: multi-part encrypt/decrypt (the payloads are 32-byte keys), `C_WrapKey` /
  `C_UnwrapKey` (the consumer needs the key bytes in its process, which is what `C_Decrypt` returns — unwrap
  would strand them on the token), `C_GenerateKey`, `C_GenerateRandom`, and the AES-GCM / key-wrap parameter
  structs. Same rule as before: the next concrete need unlocks them, nothing speculative.
- **Verified caveat — SoftHSM 2.7.0 accepts OAEP with SHA-1 only.** It advertises `CKM_RSA_PKCS_OAEP` via
  `C_GetMechanismList` and then rejects any parameter hash but SHA-1 with `CKR_ARGUMENTS_BAD` at
  `C_EncryptInit`/`C_DecryptInit`. A mechanism-presence probe therefore CANNOT see this restriction; the
  test fixture probes by attempting the operation (`SupportsRsaOaepSha256`), the SHA-1 tests are the
  unconditional floor, and the SHA-256 twins self-skip. Found the hard way: the first SHA-256 init failed
  against a byte-perfect parameter block, which read exactly like a marshalling bug and was not one.
- **The interop test is the load-bearing one**: a data key wrapped in software (.NET `RSA`, OAEP) against
  the token key's exported SPKI must be unwrapped by the token. An on-token round trip alone proves nothing
  about the parameter image — a wrong `CK_RSA_PKCS_OAEP_PARAMS` layout would be self-consistent and fail
  only against an independent implementation.

## Key generations for rolling KEKs (added 2026-09-21, issue #1 — hybrid, owner-decided)

Generations of one logical key (the envelope-encryption KEK) accumulate on the token; old generations must
keep unwrapping old data keys, and "current" is a pointer the consumer holds. Two identification schemes were
surfaced; the owner chose the **hybrid**:

- **Versioned labels are the routing key** (`kek-v1`, `kek-v2`, …): a wrapped-data-key record stores the
  label, and unwrap routes by today's exact-label `FindObjects` — no new lookup machinery, and generations
  read legibly in any HSM admin tool.
- **`CKA_ID` is written on BOTH halves of every generated pair** (same posture as certificate import:
  written, not yet searched), so a future ID-addressed consumer — smart cards — finds machine identifiers
  already present instead of needing a token backfill. `GenerateRsaKeyPair` gained the optional `id`.

**Usage flags swap with purpose** (`Pkcs11KeyPairUsage`): a signing pair carries SIGN/VERIFY, an encryption
pair DECRYPT/ENCRYPT — never both, because mixed-usage keys are the classic hygiene mistake. **Verified
caveat**: SoftHSM does not enforce usage flags — an unflagged (or wrongly-flagged) key decrypts happily
there, so the suite pins only that the flags are *written* as requested; a strict HSM is what refuses
`C_DecryptInit` on a SIGN-only key with `CKR_KEY_FUNCTION_NOT_PERMITTED`. The template being right *before*
the first strict HSM is met is the point — an encryption feature proven only against SoftHSM would be
proven against the one HSM that does not check.

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
