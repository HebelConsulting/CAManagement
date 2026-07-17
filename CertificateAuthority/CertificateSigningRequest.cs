using System.Formats.Asn1;
using System.Security.Cryptography;

namespace CertificateAuthority;

/// <summary>
/// A parsed PKCS#10 CertificationRequest (RFC 2986). <see cref="Decode"/> always
/// verifies the request's self-signature (proof of possession) — a request that
/// does not verify never becomes an instance. The CA decides which
/// <see cref="RequestedExtensions"/> to honor; they are never copied blindly.
/// </summary>
public sealed class CertificateSigningRequest
{
    public DistinguishedName Subject { get; }

    public SubjectPublicKeyInfo SubjectPublicKeyInfo { get; }

    public SignatureAlgorithm SignatureAlgorithm { get; }

    public IReadOnlyList<CertificateExtension> RequestedExtensions { get; }

    private CertificateSigningRequest(DistinguishedName subject, SubjectPublicKeyInfo subjectPublicKeyInfo,
        SignatureAlgorithm signatureAlgorithm, IReadOnlyList<CertificateExtension> requestedExtensions)
    {
        Subject = subject;
        SubjectPublicKeyInfo = subjectPublicKeyInfo;
        SignatureAlgorithm = signatureAlgorithm;
        RequestedExtensions = requestedExtensions;
    }

    public static CertificateSigningRequest Decode(byte[] der)
    {
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var request = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        // Capture the exact certificationRequestInfo bytes: they are what was signed.
        var requestInfoBytes = request.PeekEncodedValue().ToArray();
        var requestInfo = request.ReadSequence();

        var algorithmSequence = request.ReadSequence();
        var signatureAlgorithm = SignatureAlgorithmExtensions.FromOid(algorithmSequence.ReadObjectIdentifier());
        if (algorithmSequence.HasData)
        {
            algorithmSequence.ReadNull();
        }

        var signature = request.ReadBitString(out _);
        request.ThrowIfNotEmpty();

        var version = requestInfo.ReadInteger();
        if (version != 0)
        {
            throw new CryptographicException($"Unsupported PKCS#10 version {version} (expected 0).");
        }

        var subject = DistinguishedName.Decode(requestInfo);
        var subjectPublicKeyInfoBytes = requestInfo.PeekEncodedValue().ToArray();
        requestInfo.ReadSequence(); // advance past the SPKI element
        var subjectPublicKeyInfo = SubjectPublicKeyInfo.Decode(subjectPublicKeyInfoBytes);
        var requestedExtensions = ReadRequestedExtensions(requestInfo);

        VerifyProofOfPossession(signatureAlgorithm, subjectPublicKeyInfoBytes, requestInfoBytes, signature);

        return new CertificateSigningRequest(subject, subjectPublicKeyInfo, signatureAlgorithm, requestedExtensions);
    }

    private static IReadOnlyList<CertificateExtension> ReadRequestedExtensions(AsnReader requestInfo)
    {
        var attributesTag = new Asn1Tag(TagClass.ContextSpecific, 0);
        if (!requestInfo.HasData)
        {
            return [];
        }

        var extensions = new List<CertificateExtension>();
        var attributes = requestInfo.ReadSetOf(attributesTag);

        while (attributes.HasData)
        {
            var attribute = attributes.ReadSequence();
            var attributeOid = attribute.ReadObjectIdentifier();
            var values = attribute.ReadSetOf();

            if (attributeOid != Oids.ExtensionRequest)
            {
                continue; // other PKCS#9 attributes (e.g. challengePassword) are ignored
            }

            var extensionsSequence = values.ReadSequence();
            while (extensionsSequence.HasData)
            {
                var extension = extensionsSequence.ReadSequence();
                var oid = extension.ReadObjectIdentifier();
                var critical = extension.PeekTag().TagValue == (int)UniversalTagNumber.Boolean && extension.ReadBoolean();
                var value = extension.ReadOctetString();

                extensions.Add(new CertificateExtension(oid, critical, value));
            }
        }

        return extensions;
    }

    private static void VerifyProofOfPossession(
        SignatureAlgorithm algorithm, byte[] subjectPublicKeyInfo, byte[] signedData, byte[] signature)
    {
        var valid = algorithm.IsEcdsa()
            ? VerifyEcdsa(algorithm, subjectPublicKeyInfo, signedData, signature)
            : VerifyRsa(algorithm, subjectPublicKeyInfo, signedData, signature);

        if (!valid)
        {
            throw new CryptographicException("PKCS#10 signature does not verify against the embedded public key.");
        }
    }

    private static bool VerifyRsa(SignatureAlgorithm algorithm, byte[] spki, byte[] data, byte[] signature)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(spki, out _);

        return rsa.VerifyData(data, signature, algorithm.HashAlgorithmName(), RSASignaturePadding.Pkcs1);
    }

    private static bool VerifyEcdsa(SignatureAlgorithm algorithm, byte[] spki, byte[] data, byte[] signature)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(spki, out _);

        return ecdsa.VerifyData(data, signature, algorithm.HashAlgorithmName(), DSASignatureFormat.Rfc3279DerSequence);
    }
}
