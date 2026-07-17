using System.Formats.Asn1;

namespace CAManagement.X509;

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

        var segments = trimmed.StartsWith('/')
            ? SplitSegments(trimmed, startIndex: 1, separator: '/')
            : SplitSegments(trimmed, startIndex: 0, separator: ',');

        var builder = DistinguishedName.Builder();
        foreach (var segment in segments)
        {
            AddComponent(builder, segment);
        }

        return builder.Build();
    }

    /// <summary>
    /// Splits on the unescaped separator; a backslash escapes the separator and
    /// itself ("O=ACME\, Inc." / "/CN=path\/x"). Empty segments are dropped.
    /// </summary>
    private static List<string> SplitSegments(string text, int startIndex, char separator)
    {
        var segments = new List<string>();
        var current = new System.Text.StringBuilder();

        for (var i = startIndex; i < text.Length; i++)
        {
            var character = text[i];
            if (character == '\\' && i + 1 < text.Length && (text[i + 1] == separator || text[i + 1] == '\\'))
            {
                current.Append(text[++i]);
            }
            else if (character == separator)
            {
                FlushSegment(segments, current);
            }
            else
            {
                current.Append(character);
            }
        }

        FlushSegment(segments, current);

        return segments;

        static void FlushSegment(List<string> segments, System.Text.StringBuilder current)
        {
            if (current.ToString().Trim().Length > 0)
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
