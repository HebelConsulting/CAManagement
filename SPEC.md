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
- **Deliberately omitted** (add on demand): ~53 legacy protocol param structs
  (SSL3/TLS/WTLS key material, OTP, RC2/RC5/SKIPJACK/KEA/SEED/CAMELLIA/ARIA/
  GOST, PBE/PBKD2, X9.42/ECMQV/ECDH2) — untestable against SoftHSM and out of
  CA scope.
- `StructLayoutTests` locks every marshalled struct to its LP64 size; the
  Windows port must revisit these together with `NativeULong`/packing (SPEC #4).

## Console CLI
- **Spectre.Console.Cli** (replaced CommandLineParser), wired to DI via a
  `TypeRegistrar`/`TypeResolver` bridge. First command: `caconsole info`.
- `CAConsole.csproj` targets `RuntimeIdentifier=osx-arm64` so it can load the
  arm64 `libsofthsm2.so`. `caconsole info` needs an initialized token in the
  active `SOFTHSM2_CONF`; the default config reports `CKR_TOKEN_NOT_RECOGNIZED`.

## Conventions
- String **interpolation** over `+` concatenation.
- Prefer **switch expressions** (lambda notation).
- Clean code; tests written alongside implementation.
- **No architectural decisions without prior consent.**

## Future
- Separate library building **DER structures via ASN.1 reader/writer** for CA management.
- Windows support (activates the #4 platform switches).
- Optional PKCS#11 3.0 layer via `C_GetInterface` when a 3.0 module is added.
