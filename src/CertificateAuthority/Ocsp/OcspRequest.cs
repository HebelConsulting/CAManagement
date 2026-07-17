using System.Formats.Asn1;

namespace CertificateAuthority.Ocsp;

/// <summary>
/// A parsed RFC 6960 OCSPRequest (responder side). The optional request
/// signature is not evaluated — RFC 6960 does not require it, and a responder
/// answers unsigned requests. The nonce extension value is kept verbatim so the
/// response can echo it byte-identically.
/// </summary>
public sealed class OcspRequest
{
    public IReadOnlyList<OcspCertId> Requests { get; }

    /// <summary>Raw extnValue of the nonce extension, if present (echo as-is).</summary>
    public byte[]? Nonce { get; }

    private OcspRequest(IReadOnlyList<OcspCertId> requests, byte[]? nonce)
    {
        Requests = requests;
        Nonce = nonce;
    }

    public static OcspRequest Decode(byte[] der)
    {
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var request = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        var tbsRequest = request.ReadSequence();
        // optionalSignature [0] after tbsRequest is ignored on purpose.

        if (tbsRequest.HasData && tbsRequest.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            tbsRequest.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadInteger(); // version
        }

        if (tbsRequest.HasData && tbsRequest.PeekTag().TagClass == TagClass.ContextSpecific
            && tbsRequest.PeekTag().TagValue == 1)
        {
            tbsRequest.ReadEncodedValue(); // requestorName — irrelevant for answering
        }

        var requests = new List<OcspCertId>();
        var requestList = tbsRequest.ReadSequence();

        while (requestList.HasData)
        {
            var single = requestList.ReadSequence();
            requests.Add(OcspCertId.Decode(single));
            if (single.HasData)
            {
                single.ReadEncodedValue(); // singleRequestExtensions
            }
        }

        var nonce = ReadNonce(tbsRequest);

        return new OcspRequest(requests, nonce);
    }

    private static byte[]? ReadNonce(AsnReader tbsRequest)
    {
        var extensionsTag = new Asn1Tag(TagClass.ContextSpecific, 2);
        if (!tbsRequest.HasData || !tbsRequest.PeekTag().HasSameClassAndValue(extensionsTag))
        {
            return null;
        }

        var extensions = tbsRequest.ReadSequence(extensionsTag).ReadSequence();

        while (extensions.HasData)
        {
            var extension = extensions.ReadSequence();
            var oid = extension.ReadObjectIdentifier();

            if (extension.PeekTag().TagValue == (int)UniversalTagNumber.Boolean)
            {
                extension.ReadBoolean();
            }

            var value = extension.ReadOctetString();
            if (oid == Oids.OcspNonce)
            {
                return value;
            }
        }

        return null;
    }
}
