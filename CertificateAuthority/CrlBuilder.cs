using System.Formats.Asn1;

namespace CertificateAuthority;

/// <summary>
/// Builds and signs an RFC 5280 v2 CertificateList. Stateless like
/// <see cref="CertificateBuilder"/> (SPEC D5): the caller supplies the CRL number
/// and the revocation entries.
/// </summary>
public sealed class CrlBuilder
{
    public required DistinguishedName Issuer { get; init; }

    public required DateTimeOffset ThisUpdate { get; init; }

    public DateTimeOffset? NextUpdate { get; init; }

    /// <summary>RFC 5280 §5.2.3: must increase monotonically per CRL scope.</summary>
    public required ulong CrlNumber { get; init; }

    /// <summary>The issuing CA's subject key identifier, if it should be referenced.</summary>
    public byte[]? AuthorityKeyIdentifier { get; init; }

    public IReadOnlyList<RevokedCertificate> RevokedCertificates { get; init; } = [];

    public byte[] Sign(ICertificateSigner signer)
    {
        if (NextUpdate is { } nextUpdate && nextUpdate <= ThisUpdate)
        {
            throw new InvalidOperationException($"NextUpdate ({nextUpdate:O}) must be after ThisUpdate ({ThisUpdate:O}).");
        }

        var algorithm = AlgorithmIdentifier.For(signer.SignatureAlgorithm);
        var tbsCertList = EncodeTbsCertList(algorithm);
        var signature = signer.Sign(tbsCertList);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteEncodedValue(tbsCertList);
        algorithm.Encode(writer);
        writer.WriteBitString(signature);
        writer.PopSequence();

        return writer.Encode();
    }

    private byte[] EncodeTbsCertList(AlgorithmIdentifier signatureAlgorithm)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        writer.WriteInteger(1); // v2 — required because we always carry crlExtensions
        signatureAlgorithm.Encode(writer);
        Issuer.Encode(writer);
        Der.WriteTime(writer, ThisUpdate);

        if (NextUpdate is { } nextUpdate)
        {
            Der.WriteTime(writer, nextUpdate);
        }

        if (RevokedCertificates.Count > 0)
        {
            writer.PushSequence();

            foreach (var revoked in RevokedCertificates)
            {
                EncodeRevokedCertificate(writer, revoked);
            }

            writer.PopSequence();
        }

        // crlExtensions [0] EXPLICIT SEQUENCE OF Extension
        var extensionsTag = new Asn1Tag(TagClass.ContextSpecific, 0);
        writer.PushSequence(extensionsTag);
        writer.PushSequence();

        CertificateExtensions.CrlNumber(CrlNumber).Encode(writer);

        if (AuthorityKeyIdentifier is { } keyIdentifier)
        {
            CertificateExtensions.AuthorityKeyIdentifier(keyIdentifier).Encode(writer);
        }

        writer.PopSequence();
        writer.PopSequence(extensionsTag);

        writer.PopSequence();

        return writer.Encode();
    }

    private static void EncodeRevokedCertificate(AsnWriter writer, RevokedCertificate revoked)
    {
        writer.PushSequence();
        writer.WriteIntegerUnsigned(Der.TrimLeadingZeros(revoked.SerialNumber));
        Der.WriteTime(writer, revoked.RevocationDate);

        if (revoked.Reason is { } reason)
        {
            // crlEntryExtensions with a single reasonCode extension
            var inner = new AsnWriter(AsnEncodingRules.DER);
            inner.WriteEnumeratedValue(reason);

            writer.PushSequence();
            writer.PushSequence();
            writer.WriteObjectIdentifier(Oids.CrlReasonCode);
            writer.WriteOctetString(inner.Encode());
            writer.PopSequence();
            writer.PopSequence();
        }

        writer.PopSequence();
    }
}
