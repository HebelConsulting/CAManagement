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
    private readonly IReadOnlyList<(string Oid, string Value)> _components;

    internal DistinguishedName(IReadOnlyList<(string Oid, string Value)> components) =>
        _components = components;

    public IReadOnlyList<(string Oid, string Value)> Components => _components;

    public static DistinguishedNameBuilder Builder() => new();

    public void Encode(AsnWriter writer)
    {
        writer.PushSequence();

        foreach (var (oid, value) in _components)
        {
            writer.PushSetOf();
            writer.PushSequence();
            writer.WriteObjectIdentifier(oid);
            writer.WriteCharacterString(StringTypeFor(oid), value);
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
        var components = new List<(string Oid, string Value)>();
        var sequence = reader.ReadSequence();

        while (sequence.HasData)
        {
            var set = sequence.ReadSetOf();
            var attribute = set.ReadSequence();
            var oid = attribute.ReadObjectIdentifier();
            var tag = attribute.PeekTag();
            var value = attribute.ReadCharacterString((UniversalTagNumber)tag.TagValue);
            attribute.ThrowIfNotEmpty();
            set.ThrowIfNotEmpty();

            components.Add((oid, value));
        }

        return new DistinguishedName(components);
    }

    /// <summary>RFC 5280 mandates PrintableString for country; DC and email are IA5; the rest use UTF8String.</summary>
    private static UniversalTagNumber StringTypeFor(string oid) => oid switch
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
