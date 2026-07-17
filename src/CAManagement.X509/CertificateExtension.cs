using System.Formats.Asn1;

namespace CAManagement.X509;

/// <summary>
/// RFC 5280 Extension: <c>SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
/// extnValue OCTET STRING }</c>. <paramref name="Value"/> is the DER encoding of
/// the extension's inner structure.
/// </summary>
public sealed record CertificateExtension(string Oid, bool Critical, byte[] Value)
{
    public void Encode(AsnWriter writer)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier(Oid);

        if (Critical) // DEFAULT FALSE must be omitted in DER when false
        {
            writer.WriteBoolean(true);
        }

        writer.WriteOctetString(Value);
        writer.PopSequence();
    }
}
