namespace CertificateAuthority;

internal static class Der
{
    /// <summary>
    /// <c>AsnWriter.WriteIntegerUnsigned</c> requires minimal big-endian input;
    /// this trims redundant leading zero octets (keeping one for the value zero).
    /// </summary>
    internal static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        var trimmed = value.TrimStart((byte)0);
        return trimmed.IsEmpty ? value[^1..] : trimmed;
    }
}
