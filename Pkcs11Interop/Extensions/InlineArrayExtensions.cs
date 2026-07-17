using System.Runtime.InteropServices;
using System.Text;
using Pkcs11Interop.DataStructures;

namespace Pkcs11Interop.Extensions;

/// <summary>
/// Converts PKCS#11 fixed-length text fields to strings. Cryptoki pads these
/// fields with spaces (0x20) rather than null-terminating them, so trailing
/// spaces and nulls are trimmed.
/// </summary>
public static class InlineArrayExtensions
{
    public static string AsPkcs11String(this InlineArray16 array) => ToTrimmedString(MemoryMarshal.CreateReadOnlySpan(ref array.Element0, 16));

    public static string AsPkcs11String(this InlineArray32 array) => ToTrimmedString(MemoryMarshal.CreateReadOnlySpan(ref array.Element0, 32));

    public static string AsPkcs11String(this InlineArray64 array) => ToTrimmedString(MemoryMarshal.CreateReadOnlySpan(ref array.Element0, 64));

    private static string ToTrimmedString(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes).TrimEnd(' ', '\0');
}
