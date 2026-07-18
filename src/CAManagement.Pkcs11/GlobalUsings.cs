// ---------------------------------------------------------------------------
// Platform centralization (SPEC decision #4).
//
// PKCS#11 CK_ULONG maps to C `unsigned long`, whose width is ABI-dependent:
//   * Unix LP64 (Linux, macOS)  -> 8 bytes -> System.UInt64  (net10.0 TFM)
//   * Windows LLP64             -> 4 bytes -> System.UInt32  (net10.0-windows TFM)
//
// The WINDOWS symbol is defined automatically by the net10.0-windows target.
// Windows also mandates 1-byte struct packing (#pragma pack(1) in its
// pkcs11.h) — see Pkcs11Layout.Pack.
// ---------------------------------------------------------------------------

#if WINDOWS
global using NativeULong = System.UInt32;
#else
global using NativeULong = System.UInt64;
#endif

namespace CAManagement.Pkcs11;

/// <summary>Centralized native layout constants (SPEC decision #4).</summary>
internal static class Pkcs11Layout
{
#if WINDOWS
    /// <summary>Windows' pkcs11.h forces <c>#pragma pack(1)</c>.</summary>
    public const int Pack = 1;
    private const int ExpectedWidth = 4;
#else
    /// <summary>Unix LP64: natural alignment.</summary>
    public const int Pack = 0;
    private const int ExpectedWidth = 8;
#endif

    // Compile-time guard: divides by zero at compile time if the NativeULong
    // alias and the target platform ever disagree.
    private const int WidthGuard = 1 / (sizeof(NativeULong) == ExpectedWidth ? 1 : 0);
}
