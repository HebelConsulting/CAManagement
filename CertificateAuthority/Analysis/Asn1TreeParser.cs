using System.Formats.Asn1;

namespace CertificateAuthority.Analysis;

/// <summary>
/// Parses arbitrary BER/DER into a tree of <see cref="Asn1Node"/>s. BER rules are
/// used deliberately: analysis wants acceptance (CMS/PKCS#7 blobs commonly use
/// BER indefinite lengths), unlike the DER-strict production encoders. OCTET
/// STRING and BIT STRING contents that are themselves valid encodings are
/// descended into (extension values, wrapped keys), like certutil does.
/// </summary>
public static class Asn1TreeParser
{
    private const int HexPreviewBytes = 24;

    public static List<Asn1Node> Parse(ReadOnlyMemory<byte> data) => ParseElements(data, baseOffset: 0);

    private static List<Asn1Node> ParseElements(ReadOnlyMemory<byte> data, int baseOffset)
    {
        var nodes = new List<Asn1Node>();
        var position = 0;

        while (position < data.Length)
        {
            var slice = data.Span[position..];
            var tag = Asn1Tag.Decode(slice, out _);
            AsnDecoder.ReadEncodedValue(slice, AsnEncodingRules.BER, out var contentOffset, out var contentLength, out var bytesConsumed);

            var content = data.Slice(position + contentOffset, contentLength);
            var element = data.Slice(position, bytesConsumed);

            nodes.Add(tag.IsConstructed
                ? new Asn1Node
                {
                    TagName = TagNameOf(tag),
                    Offset = baseOffset + position,
                    Length = bytesConsumed,
                    Children = ParseElements(content, baseOffset + position + contentOffset),
                }
                : CreatePrimitiveNode(tag, element, content, baseOffset + position, bytesConsumed, baseOffset + position + contentOffset));

            position += bytesConsumed;
        }

        return nodes;
    }

    private static Asn1Node CreatePrimitiveNode(
        Asn1Tag tag, ReadOnlyMemory<byte> element, ReadOnlyMemory<byte> content, int offset, int length, int contentOffset)
    {
        var (value, decodedOid) = RenderValue(tag, element.Span, content.Span);
        var children = TryParseEncapsulated(tag, content, contentOffset);

        return new Asn1Node
        {
            TagName = TagNameOf(tag),
            Offset = offset,
            Length = length,
            Value = children.Count > 0 ? $"{value}, encapsulates:" : value,
            DecodedOid = decodedOid,
            Children = children,
        };
    }

    /// <summary>OCTET STRING always; BIT STRING when it has no unused bits (skip the leading count octet).</summary>
    private static List<Asn1Node> TryParseEncapsulated(Asn1Tag tag, ReadOnlyMemory<byte> content, int contentOffset)
    {
        var candidate = tag switch
        {
            { TagClass: TagClass.Universal, TagValue: (int)UniversalTagNumber.OctetString } => content,
            { TagClass: TagClass.Universal, TagValue: (int)UniversalTagNumber.BitString }
                when content.Length > 1 && content.Span[0] == 0 => content[1..],
            _ => ReadOnlyMemory<byte>.Empty,
        };

        if (candidate.Length < 2)
        {
            return [];
        }

        try
        {
            var innerOffset = contentOffset + (candidate.Length == content.Length ? 0 : 1);
            return ParseElements(candidate, innerOffset);
        }
        catch (AsnContentException)
        {
            return []; // not nested DER — plain payload bytes
        }
    }

    private static (string Value, string? DecodedOid) RenderValue(Asn1Tag tag, ReadOnlySpan<byte> element, ReadOnlySpan<byte> content)
    {
        if (tag.TagClass != TagClass.Universal)
        {
            return (HexPreview(content), null);
        }

        try
        {
            switch ((UniversalTagNumber)tag.TagValue)
            {
                case UniversalTagNumber.Boolean:
                    return (AsnDecoder.ReadBoolean(element, AsnEncodingRules.BER, out _) ? "TRUE" : "FALSE", null);
                case UniversalTagNumber.Integer:
                case UniversalTagNumber.Enumerated:
                    return (RenderInteger(content), null);
                case UniversalTagNumber.Null:
                    return ("NULL", null);
                case UniversalTagNumber.ObjectIdentifier:
                    var oid = AsnDecoder.ReadObjectIdentifier(element, AsnEncodingRules.BER, out _);
                    return (OidNames.For(oid) is { } name ? $"{oid} ({name})" : oid, oid);
                case UniversalTagNumber.UtcTime:
                    return (AsnDecoder.ReadUtcTime(element, AsnEncodingRules.BER, out _).ToString("yyyy-MM-dd HH:mm:ss 'UTC'"), null);
                case UniversalTagNumber.GeneralizedTime:
                    return (AsnDecoder.ReadGeneralizedTime(element, AsnEncodingRules.BER, out _).ToString("yyyy-MM-dd HH:mm:ss 'UTC'"), null);
                case UniversalTagNumber.UTF8String:
                case UniversalTagNumber.PrintableString:
                case UniversalTagNumber.IA5String:
                case UniversalTagNumber.BMPString:
                case UniversalTagNumber.T61String:
                    var text = AsnDecoder.ReadCharacterString(element, AsnEncodingRules.BER, (UniversalTagNumber)tag.TagValue, out _);
                    return ($"\"{text}\"", null);
                case UniversalTagNumber.BitString:
                    var unused = content.Length > 0 ? content[0] : 0;
                    var bits = content.Length > 1 ? content[1..] : [];
                    return (unused == 0 ? HexPreview(bits) : $"{HexPreview(bits)} ({unused} unused bits)", null);
                default:
                    return (HexPreview(content), null);
            }
        }
        catch (AsnContentException)
        {
            return (HexPreview(content), null);
        }
    }

    private static string RenderInteger(ReadOnlySpan<byte> content) => content.Length <= 8
        ? new System.Numerics.BigInteger(content, isUnsigned: false, isBigEndian: true).ToString()
        : HexPreview(content);

    private static string HexPreview(ReadOnlySpan<byte> bytes) => bytes.Length switch
    {
        0 => "(empty)",
        <= HexPreviewBytes => Convert.ToHexString(bytes),
        _ => $"{Convert.ToHexString(bytes[..HexPreviewBytes])}… ({bytes.Length} bytes)",
    };

    private static string TagNameOf(Asn1Tag tag) => tag.TagClass switch
    {
        TagClass.Universal => (UniversalTagNumber)tag.TagValue switch
        {
            UniversalTagNumber.Boolean => "BOOLEAN",
            UniversalTagNumber.Integer => "INTEGER",
            UniversalTagNumber.BitString => "BIT STRING",
            UniversalTagNumber.OctetString => "OCTET STRING",
            UniversalTagNumber.Null => "NULL",
            UniversalTagNumber.ObjectIdentifier => "OBJECT IDENTIFIER",
            UniversalTagNumber.UTF8String => "UTF8String",
            UniversalTagNumber.Sequence => "SEQUENCE",
            UniversalTagNumber.Set => "SET",
            UniversalTagNumber.PrintableString => "PrintableString",
            UniversalTagNumber.T61String => "T61String",
            UniversalTagNumber.IA5String => "IA5String",
            UniversalTagNumber.UtcTime => "UTCTime",
            UniversalTagNumber.GeneralizedTime => "GeneralizedTime",
            UniversalTagNumber.BMPString => "BMPString",
            UniversalTagNumber.Enumerated => "ENUMERATED",
            var other => other.ToString(),
        },
        TagClass.ContextSpecific => $"[{tag.TagValue}]",
        TagClass.Application => $"[APPLICATION {tag.TagValue}]",
        _ => $"[PRIVATE {tag.TagValue}]",
    };
}
