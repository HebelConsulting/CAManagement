namespace CAManagement.X509.Analysis;

/// <summary>One element of a parsed DER tree.</summary>
public sealed class Asn1Node
{
    /// <summary>Rendered tag, e.g. "SEQUENCE", "INTEGER", "[0]".</summary>
    public required string TagName { get; init; }

    /// <summary>Absolute offset of the element within the document.</summary>
    public required int Offset { get; init; }

    /// <summary>Total TLV length in bytes.</summary>
    public required int Length { get; init; }

    /// <summary>Rendered primitive value ("2", "1.2.840.113549.1.1.11 (sha256WithRSAEncryption)", hex preview).</summary>
    public string? Value { get; init; }

    /// <summary>Dotted OID when the node is an OBJECT IDENTIFIER (for annotators).</summary>
    public string? DecodedOid { get; init; }

    /// <summary>Raw content bytes for non-ASN.1 wire nodes (e.g. SSH strings), for nested parsing.</summary>
    public byte[]? RawContent { get; init; }

    /// <summary>Schema field name set by an annotator, e.g. "serialNumber".</summary>
    public string? Name { get; set; }

    /// <summary>Human explanation set by an annotator.</summary>
    public string? Explanation { get; set; }

    public List<Asn1Node> Children { get; init; } = [];
}
