using System.Formats.Asn1;

namespace CertificateAuthority;

/// <summary>
/// Parses DN strings in OpenSSL slash form or comma form, with optional
/// per-component string-type annotations ("CN=[PrintableString]www.test.org").
/// The annotation prefix form was chosen over a "value@Type" suffix because '@'
/// legitimately occurs in emailAddress values.
/// </summary>
internal static class DistinguishedNameParser
{
    internal static DistinguishedName Parse(string text)
    {
        var trimmed = text.Trim();
        if (trimmed.Length == 0)
        {
            throw new FormatException("The distinguished name string is empty.");
        }

        IReadOnlyList<string> segments = trimmed.StartsWith('/')
            ? SplitSlashSegments(trimmed)
            : trimmed.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

        var builder = DistinguishedName.Builder();
        foreach (var segment in segments)
        {
            AddComponent(builder, segment);
        }

        return builder.Build();
    }

    /// <summary>Splits "/K=V/K=V" on unescaped '/', unescaping "\/" and "\\".</summary>
    private static List<string> SplitSlashSegments(string text)
    {
        var segments = new List<string>();
        var current = new System.Text.StringBuilder();

        for (var i = 1; i < text.Length; i++) // skip the leading '/'
        {
            var character = text[i];
            switch (character)
            {
                case '\\' when i + 1 < text.Length && text[i + 1] is '/' or '\\':
                    current.Append(text[++i]);
                    break;
                case '/':
                    FlushSegment(segments, current);
                    break;
                default:
                    current.Append(character);
                    break;
            }
        }

        FlushSegment(segments, current);

        return segments;

        static void FlushSegment(List<string> segments, System.Text.StringBuilder current)
        {
            if (current.Length > 0)
            {
                segments.Add(current.ToString());
            }
            current.Clear();
        }
    }

    private static void AddComponent(DistinguishedNameBuilder builder, string segment)
    {
        var parts = segment.Split('=', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || parts[0].Length == 0)
        {
            throw new FormatException($"Invalid distinguished name component '{segment}' (expected key=value).");
        }

        var oid = OidForKey(parts[0]);
        var (stringType, value) = SplitAnnotation(parts[1]);

        if (value.Length == 0)
        {
            throw new FormatException($"Attribute {parts[0]} must not be empty.");
        }

        builder.Add(oid, value, stringType);
    }

    private static (UniversalTagNumber? StringType, string Value) SplitAnnotation(string value)
    {
        if (!value.StartsWith('[') || value.IndexOf(']') is not (> 1 and var end))
        {
            return (null, value);
        }

        return (StringTypeFromName(value[1..end]), value[(end + 1)..]);
    }

    private static UniversalTagNumber StringTypeFromName(string name) =>
        name.Replace("-", "").ToUpperInvariant() switch
        {
            "UTF8STRING" or "UTF8" => UniversalTagNumber.UTF8String,
            "PRINTABLESTRING" or "PRINTABLE" => UniversalTagNumber.PrintableString,
            "IA5STRING" or "IA5" => UniversalTagNumber.IA5String,
            "BMPSTRING" or "BMP" => UniversalTagNumber.BMPString,
            "T61STRING" or "T61" or "TELETEXSTRING" => UniversalTagNumber.T61String,
            _ => throw new FormatException(
                $"Unknown string type annotation '[{name}]' (supported: UTF8String, PrintableString, IA5String, BMPString, T61String)."),
        };

    private static string OidForKey(string key) => key.ToUpperInvariant() switch
    {
        "CN" => Oids.CommonName,
        "O" => Oids.Organization,
        "OU" => Oids.OrganizationalUnit,
        "C" => Oids.Country,
        "L" => Oids.Locality,
        "ST" => Oids.StateOrProvince,
        "DC" => Oids.DomainComponent,
        "E" or "EMAILADDRESS" => Oids.EmailAddress,
        "SERIALNUMBER" => Oids.SerialNumberAttribute,
        var other when other.Contains('.') => key, // dotted OID used directly
        _ => throw new FormatException($"Unsupported distinguished name attribute '{key}'."),
    };
}
