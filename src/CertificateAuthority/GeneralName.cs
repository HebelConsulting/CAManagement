using System.Formats.Asn1;
using System.Net;

namespace CertificateAuthority;

public enum GeneralNameKind
{
    Email,     // rfc822Name [1]
    DnsName,   // dNSName [2]
    Uri,       // uniformResourceIdentifier [6]
    IpAddress, // iPAddress [7]
}

/// <summary>An RFC 5280 GeneralName (the subset used by SAN/IAN/CRLDP/AIA).</summary>
public sealed record GeneralName(GeneralNameKind Kind, string Value)
{
    public static GeneralName Dns(string name) => new(GeneralNameKind.DnsName, name);

    public static GeneralName Email(string address) => new(GeneralNameKind.Email, address);

    public static GeneralName Uri(string uri) => new(GeneralNameKind.Uri, uri);

    public static GeneralName Ip(string address) => new(GeneralNameKind.IpAddress, address);

    internal void Encode(AsnWriter writer)
    {
        switch (Kind)
        {
            case GeneralNameKind.Email:
                writer.WriteCharacterString(UniversalTagNumber.IA5String, Value, new Asn1Tag(TagClass.ContextSpecific, 1));
                break;
            case GeneralNameKind.DnsName:
                writer.WriteCharacterString(UniversalTagNumber.IA5String, Value, new Asn1Tag(TagClass.ContextSpecific, 2));
                break;
            case GeneralNameKind.Uri:
                writer.WriteCharacterString(UniversalTagNumber.IA5String, Value, new Asn1Tag(TagClass.ContextSpecific, 6));
                break;
            case GeneralNameKind.IpAddress:
                writer.WriteOctetString(IPAddress.Parse(Value).GetAddressBytes(), new Asn1Tag(TagClass.ContextSpecific, 7));
                break;
        }
    }
}
