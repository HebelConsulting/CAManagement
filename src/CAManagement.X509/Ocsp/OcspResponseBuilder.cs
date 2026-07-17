using System.Formats.Asn1;
using System.Security.Cryptography;

namespace CAManagement.X509.Ocsp;

/// <summary>
/// Builds and signs an RFC 6960 OCSPResponse with a BasicOCSPResponse payload.
/// Stateless like the other builders (SPEC D5): the caller supplies times and
/// statuses. The responder is identified byKey (SHA-1 of the responder's public
/// key bits) — robust against name re-encoding differences.
/// </summary>
public sealed class OcspResponseBuilder
{
    /// <summary>The responder's public key (usually the CA key); hashed for the byKey ResponderID.</summary>
    public required SubjectPublicKeyInfo ResponderPublicKey { get; init; }

    public required DateTimeOffset ProducedAt { get; init; }

    public required IReadOnlyList<OcspSingleResponse> Responses { get; init; }

    /// <summary>Nonce extnValue to echo verbatim (from <see cref="OcspRequest.Nonce"/>).</summary>
    public byte[]? Nonce { get; init; }

    /// <summary>DER certificates to embed (typically the responder/CA certificate).</summary>
    public IReadOnlyList<byte[]> Certificates { get; init; } = [];

    public byte[] Sign(ICertificateSigner signer)
    {
        var algorithm = AlgorithmIdentifier.For(signer.SignatureAlgorithm);
        var tbsResponseData = EncodeResponseData();
        var signature = signer.Sign(tbsResponseData);

        var basic = new AsnWriter(AsnEncodingRules.DER);
        basic.PushSequence();
        basic.WriteEncodedValue(tbsResponseData);
        algorithm.Encode(basic);
        basic.WriteBitString(signature);

        if (Certificates.Count > 0)
        {
            var certsTag = new Asn1Tag(TagClass.ContextSpecific, 0);
            basic.PushSequence(certsTag);
            basic.PushSequence();
            foreach (var certificate in Certificates)
            {
                basic.WriteEncodedValue(certificate);
            }
            basic.PopSequence();
            basic.PopSequence(certsTag);
        }

        basic.PopSequence();

        return WrapResponse(basic.Encode());
    }

    /// <summary>An unsigned non-successful response (malformedRequest, tryLater, ...).</summary>
    public static byte[] CreateError(OcspResponseStatus status)
    {
        if (status == OcspResponseStatus.Successful)
        {
            throw new ArgumentException("A successful response needs response bytes — use Sign.", nameof(status));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteEnumeratedValue(status);
        writer.PopSequence();

        return writer.Encode();
    }

    private static byte[] WrapResponse(byte[] basicResponseDer)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteEnumeratedValue(OcspResponseStatus.Successful);

        var responseBytesTag = new Asn1Tag(TagClass.ContextSpecific, 0);
        writer.PushSequence(responseBytesTag);
        writer.PushSequence();
        writer.WriteObjectIdentifier(Oids.OcspBasicResponse);
        writer.WriteOctetString(basicResponseDer);
        writer.PopSequence();
        writer.PopSequence(responseBytesTag);

        writer.PopSequence();

        return writer.Encode();
    }

    private byte[] EncodeResponseData()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        // version v1 is the DEFAULT and therefore omitted.

        // responderID byKey: [2] EXPLICIT KeyHash (SHA-1 of the key bits, RFC 6960 §4.2.1)
        var byKeyTag = new Asn1Tag(TagClass.ContextSpecific, 2);
        writer.PushSequence(byKeyTag);
        writer.WriteOctetString(SHA1.HashData(ResponderPublicKey.PublicKeyBytes));
        writer.PopSequence(byKeyTag);

        Der.WriteGeneralizedTime(writer, ProducedAt);

        writer.PushSequence();
        foreach (var response in Responses)
        {
            EncodeSingleResponse(writer, response);
        }
        writer.PopSequence();

        if (Nonce is { } nonce)
        {
            var extensionsTag = new Asn1Tag(TagClass.ContextSpecific, 1);
            writer.PushSequence(extensionsTag);
            writer.PushSequence();
            writer.PushSequence();
            writer.WriteObjectIdentifier(Oids.OcspNonce);
            writer.WriteOctetString(nonce);
            writer.PopSequence();
            writer.PopSequence();
            writer.PopSequence(extensionsTag);
        }

        writer.PopSequence();

        return writer.Encode();
    }

    private static void EncodeSingleResponse(AsnWriter writer, OcspSingleResponse response)
    {
        writer.PushSequence();
        response.CertId.Encode(writer);

        switch (response.Status)
        {
            case OcspCertStatus.Good:
                writer.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 0)); // [0] IMPLICIT NULL
                break;

            case OcspCertStatus.Revoked:
                var revokedTag = new Asn1Tag(TagClass.ContextSpecific, 1);
                writer.PushSequence(revokedTag);
                Der.WriteGeneralizedTime(writer, response.RevocationTime
                    ?? throw new InvalidOperationException("A revoked status needs a RevocationTime."));

                if (response.RevocationReason is { } reason)
                {
                    var reasonTag = new Asn1Tag(TagClass.ContextSpecific, 0);
                    writer.PushSequence(reasonTag);
                    writer.WriteEnumeratedValue(reason);
                    writer.PopSequence(reasonTag);
                }

                writer.PopSequence(revokedTag);
                break;

            case OcspCertStatus.Unknown:
                writer.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 2)); // [2] IMPLICIT NULL
                break;
        }

        Der.WriteGeneralizedTime(writer, response.ThisUpdate);

        if (response.NextUpdate is { } nextUpdate)
        {
            var nextUpdateTag = new Asn1Tag(TagClass.ContextSpecific, 0);
            writer.PushSequence(nextUpdateTag);
            Der.WriteGeneralizedTime(writer, nextUpdate);
            writer.PopSequence(nextUpdateTag);
        }

        writer.PopSequence();
    }
}
