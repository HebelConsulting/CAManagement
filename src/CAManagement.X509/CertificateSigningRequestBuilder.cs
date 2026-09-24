using System.Formats.Asn1;

namespace CAManagement.X509;

/// <summary>
/// Builds and signs a PKCS#10 CertificationRequest (RFC 2986) — the counterpart to
/// <see cref="CertificateSigningRequest.Decode"/>, which until now could only read one.
/// </summary>
/// <remarks>
/// The signature is produced through <see cref="ICertificateSigner"/>, the same seam the CA signs with, so a
/// request can be signed by a key that never leaves a token: a smartcard enrolment produces the CSR on the
/// card itself. That is the reason this exists — without it the only way to turn a token-resident key into a
/// certificate is vendor tooling, which is per-vendor and therefore per-customer.
///
/// The self-signature IS the proof of possession: it is what lets a CA believe the requester holds the
/// private half. <see cref="CertificateSigningRequest.Decode"/> verifies it and refuses otherwise, so a
/// request built here is checked by the same rule it will meet at the CA.
/// </remarks>
public sealed class CertificateSigningRequestBuilder
{
    public required DistinguishedName Subject { get; init; }

    public required SubjectPublicKeyInfo SubjectPublicKeyInfo { get; init; }

    /// <summary>
    /// Extensions to REQUEST. A CA is free to ignore them — <see cref="CertificateSigningRequest"/> says so
    /// in as many words — so these are an ask, never a grant.
    /// </summary>
    public IReadOnlyList<CertificateExtension> RequestedExtensions { get; init; } = [];

    public byte[] Sign(ICertificateSigner signer)
    {
        var algorithm = AlgorithmIdentifier.For(signer.SignatureAlgorithm);
        var requestInfo = EncodeRequestInfo();
        var signature = signer.Sign(requestInfo);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteEncodedValue(requestInfo);
        algorithm.Encode(writer);
        writer.WriteBitString(signature);
        writer.PopSequence();

        return writer.Encode();
    }

    private byte[] EncodeRequestInfo()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        writer.WriteInteger(0); // version v1
        Subject.Encode(writer);
        SubjectPublicKeyInfo.Encode(writer);

        // attributes [0] IMPLICIT SET OF Attribute — the tag is NOT optional even when there is nothing to
        // say: a CertificationRequestInfo without it does not parse, and the failure surfaces at the CA
        // rather than here.
        var attributes = new Asn1Tag(TagClass.ContextSpecific, 0);
        writer.PushSetOf(attributes);
        if (RequestedExtensions.Count > 0)
        {
            // Attribute ::= SEQUENCE { type OID, values SET OF ANY } — one attribute, extensionRequest,
            // whose single value is the SEQUENCE OF Extension.
            writer.PushSequence();
            writer.WriteObjectIdentifier(Oids.ExtensionRequest);
            writer.PushSetOf();
            writer.PushSequence();
            foreach (var extension in RequestedExtensions)
            {
                extension.Encode(writer);
            }

            writer.PopSequence();
            writer.PopSetOf();
            writer.PopSequence();
        }

        writer.PopSetOf(attributes);
        writer.PopSequence();

        return writer.Encode();
    }
}
