using System.Formats.Asn1;

namespace CertificateAuthority;

internal static class Der
{
    /// <summary>RFC 5280 Time: UTCTime for dates before 2050, GeneralizedTime after (§4.1.2.5).</summary>
    internal static void WriteTime(AsnWriter writer, DateTimeOffset value)
    {
        var utc = value.UtcDateTime;
        var truncated = new DateTimeOffset(utc.Year, utc.Month, utc.Day, utc.Hour, utc.Minute, utc.Second, TimeSpan.Zero);

        if (truncated.Year < 2050)
        {
            writer.WriteUtcTime(truncated);
        }
        else
        {
            writer.WriteGeneralizedTime(truncated, omitFractionalSeconds: true);
        }
    }

    /// <summary>OCSP mandates GeneralizedTime regardless of year; truncated to whole seconds.</summary>
    internal static void WriteGeneralizedTime(AsnWriter writer, DateTimeOffset value)
    {
        var utc = value.UtcDateTime;
        writer.WriteGeneralizedTime(
            new DateTimeOffset(utc.Year, utc.Month, utc.Day, utc.Hour, utc.Minute, utc.Second, TimeSpan.Zero),
            omitFractionalSeconds: true);
    }

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
