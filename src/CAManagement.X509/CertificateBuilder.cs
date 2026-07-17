using System.Formats.Asn1;
using System.Security.Cryptography;

namespace CAManagement.X509;

/// <summary>
/// Builds and signs an RFC 5280 v3 certificate. Stateless (SPEC D5): the caller
/// supplies validity and (optionally) the serial; without one, a random 16-byte
/// positive serial is generated (RFC 5280 §4.1.2.2, CABF ≥64-bit entropy).
/// </summary>
public sealed class CertificateBuilder
{
    public required DistinguishedName Subject { get; init; }

    public required SubjectPublicKeyInfo SubjectPublicKeyInfo { get; init; }

    public required DateTimeOffset NotBefore { get; init; }

    public required DateTimeOffset NotAfter { get; init; }

    /// <summary>Big-endian positive integer; defaults to 16 random bytes.</summary>
    public byte[]? SerialNumber { get; init; }

    public IReadOnlyList<CertificateExtension> Extensions { get; init; } = [];

    public byte[] SignSelfSigned(ICertificateSigner signer) => Sign(Subject, signer);

    public byte[] Sign(DistinguishedName issuer, ICertificateSigner signer)
    {
        if (NotAfter <= NotBefore)
        {
            throw new InvalidOperationException($"NotAfter ({NotAfter:O}) must be after NotBefore ({NotBefore:O}).");
        }

        var algorithm = AlgorithmIdentifier.For(signer.SignatureAlgorithm);
        var tbsCertificate = EncodeTbsCertificate(issuer, algorithm);
        var signature = signer.Sign(tbsCertificate);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteEncodedValue(tbsCertificate);
        algorithm.Encode(writer);
        writer.WriteBitString(signature);
        writer.PopSequence();

        return writer.Encode();
    }

    private byte[] EncodeTbsCertificate(DistinguishedName issuer, AlgorithmIdentifier signatureAlgorithm)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        // version [0] EXPLICIT INTEGER v3(2)
        writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        writer.WriteInteger(2);
        writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

        writer.WriteIntegerUnsigned(Der.TrimLeadingZeros(SerialNumber ?? CreateRandomSerialNumber()));
        signatureAlgorithm.Encode(writer);
        issuer.Encode(writer);

        writer.PushSequence();
        Der.WriteTime(writer, NotBefore);
        Der.WriteTime(writer, NotAfter);
        writer.PopSequence();

        Subject.Encode(writer);
        SubjectPublicKeyInfo.Encode(writer);

        if (Extensions.Count > 0)
        {
            // extensions [3] EXPLICIT SEQUENCE OF Extension
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.PushSequence();

            foreach (var extension in Extensions)
            {
                extension.Encode(writer);
            }

            writer.PopSequence();
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
        }

        writer.PopSequence();

        return writer.Encode();
    }

    private static byte[] CreateRandomSerialNumber()
    {
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F; // keep the INTEGER positive

        return serial;
    }
}
