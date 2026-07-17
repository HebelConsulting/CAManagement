// ---------------------------------------------------------------------------
// Platform centralization (SPEC decision #4).
//
// PKCS#11 CK_ULONG maps to C `unsigned long`, whose width is ABI-dependent:
//   * Unix LP64 (Linux, macOS)      -> 8 bytes  -> System.UInt64   (current target)
//   * Windows LLP64                 -> 4 bytes  -> System.UInt32   (future)
//
// This single alias is the ONE place to switch when Windows support is added.
// Note: a full single-binary Windows port also needs the 1-byte struct packing
// variant used by Windows' pkcs11.h (#pragma pack(1)); see Pkcs11Layout below.
// On our Unix target, structs use natural alignment (default packing).
// ---------------------------------------------------------------------------

global using NativeULong = System.UInt64;

namespace CAManagement.Pkcs11;

/// <summary>Centralized native layout constants (SPEC decision #4).</summary>
internal static class Pkcs11Layout
{
    /// <summary>
    /// Struct packing for the current (Unix LP64) target: natural alignment.
    /// Windows' pkcs11.h forces <c>#pragma pack(1)</c>; switch here when porting.
    /// </summary>
    public const int Pack = 0;
}
