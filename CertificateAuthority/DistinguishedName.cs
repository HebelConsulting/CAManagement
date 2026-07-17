using System.Formats.Asn1;

namespace CertificateAuthority;

/// <summary>
/// RFC 5280 Name (RDNSequence). Components are stored and encoded in the order
/// added — add the most significant component first (e.g. Country → Organization
/// → CommonName). Each RDN is single-valued (multi-valued RDNs are out of scope
/// for v1).
/// </summary>
public sealed class DistinguishedName
{
    private readonly IReadOnlyList<DistinguishedNameComponent> _components;

    internal DistinguishedName(IReadOnlyList<DistinguishedNameComponent> components) =>
        _components = components;

    public IReadOnlyList<DistinguishedNameComponent> Components => _components;

    public static DistinguishedNameBuilder Builder() => new();

    /// <summary>
    /// Parses a DN string: OpenSSL slash form ("/C=CH/O=Example/CN=name", escapes
    /// \/ and \\) when starting with '/', otherwise comma form ("C=CH, O=Example,
    /// CN=name"). Values may carry a string-type annotation prefix, e.g.
    /// "CN=[PrintableString]www.test.org" ("UTF8-String" spelling accepted).
    /// Components are encoded in the given order.
    /// </summary>
    public static DistinguishedName Parse(string text) => DistinguishedNameParser.Parse(text);

    public void Encode(AsnWriter writer)
    {
        writer.PushSequence();

        foreach (var component in _components)
        {
            writer.PushSetOf();
            writer.PushSequence();
            writer.WriteObjectIdentifier(component.Oid);
            writer.WriteCharacterString(component.StringType ?? StringTypeFor(component.Oid), component.Value);
            writer.PopSequence();
            writer.PopSetOf();
        }

        writer.PopSequence();
    }

    public byte[] Encode()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        Encode(writer);
        return writer.Encode();
    }

    public static DistinguishedName Decode(byte[] der)
    {
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var name = Decode(reader);
        reader.ThrowIfNotEmpty();

        return name;
    }

    internal static DistinguishedName Decode(AsnReader reader)
    {
        var components = new List<DistinguishedNameComponent>();
        var sequence = reader.ReadSequence();

        while (sequence.HasData)
        {
            var set = sequence.ReadSetOf();
            var attribute = set.ReadSequence();
            var oid = attribute.ReadObjectIdentifier();
            var stringType = (UniversalTagNumber)attribute.PeekTag().TagValue;
            var value = attribute.ReadCharacterString(stringType);
            attribute.ThrowIfNotEmpty();
            set.ThrowIfNotEmpty();

            // Remember the encoding only when it differs from our default, so
            // re-encoding is byte-faithful without cluttering the common case.
            components.Add(new DistinguishedNameComponent(
                oid, value, stringType == StringTypeFor(oid) ? null : stringType));
        }

        return new DistinguishedName(components);
    }

    /// <summary>RFC 5280 mandates PrintableString for country; DC and email are IA5; the rest use UTF8String.</summary>
    internal static UniversalTagNumber StringTypeFor(string oid) => oid switch
    {
        Oids.Country => UniversalTagNumber.PrintableString,
        Oids.SerialNumberAttribute => UniversalTagNumber.PrintableString,
        Oids.DomainComponent => UniversalTagNumber.IA5String,
        Oids.EmailAddress => UniversalTagNumber.IA5String,
        _ => UniversalTagNumber.UTF8String,
    };

    public override string ToString() => string.Join(", ", _components.Select(c => $"{ShortNameFor(c.Oid)}={c.Value}"));

    private static string ShortNameFor(string oid) => oid switch
    {
        Oids.CommonName => "CN",
        Oids.Country => "C",
        Oids.Locality => "L",
        Oids.StateOrProvince => "ST",
        Oids.Organization => "O",
        Oids.OrganizationalUnit => "OU",
        Oids.SerialNumberAttribute => "serialNumber",
        Oids.DomainComponent => "DC",
        Oids.EmailAddress => "E",
        _ => oid,
    };
}
