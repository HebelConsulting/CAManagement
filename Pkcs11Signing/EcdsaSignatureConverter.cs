using System.Formats.Asn1;

namespace Pkcs11Signing;

/// <summary>
/// PKCS#11 returns ECDSA signatures as the raw fixed-width concatenation r||s
/// (IEEE P1363); X.509 signatureValue expects DER <c>SEQUENCE { r INTEGER, s INTEGER }</c>
/// (RFC 3279 §2.2.3). This converter is deliberately part of the PKCS#11 adapter —
/// it is a PKCS#11 quirk, not a concern of the DER library.
/// </summary>
public static class EcdsaSignatureConverter
{
    public static byte[] RawToDer(byte[] rawSignature)
    {
        if (rawSignature.Length == 0 || rawSignature.Length % 2 != 0)
        {
            throw new ArgumentException($"Raw ECDSA signature must have even length, got {rawSignature.Length} bytes.");
        }

        var half = rawSignature.Length / 2;
        var writer = new AsnWriter(AsnEncodingRules.DER);

        writer.PushSequence();
        writer.WriteIntegerUnsigned(TrimLeadingZeros(rawSignature.AsSpan(0, half)));
        writer.WriteIntegerUnsigned(TrimLeadingZeros(rawSignature.AsSpan(half)));
        writer.PopSequence();

        return writer.Encode();
    }

    /// <summary>
    /// The fixed-width halves are zero-padded; WriteIntegerUnsigned requires
    /// minimal big-endian input (it only re-adds the high-bit 0x00 prefix).
    /// </summary>
    private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        var trimmed = value.TrimStart((byte)0);
        return trimmed.IsEmpty ? value[^1..] : trimmed;
    }
}
