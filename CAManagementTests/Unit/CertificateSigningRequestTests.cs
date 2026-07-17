using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateAuthority;

namespace CAManagementTests.Unit;

public sealed class CertificateSigningRequestTests
{
    private static byte[] CreateRsaCsr(RSA key) =>
        new CertificateRequest(new X500DistinguishedName("CN=Requester, O=Example"), key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();

    private static byte[] CreateEcdsaCsrWithSan(ECDsa key)
    {
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=req.example.test"), key, HashAlgorithmName.SHA256);

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("req.example.test");
        request.CertificateExtensions.Add(sanBuilder.Build());

        return request.CreateSigningRequest();
    }

    [Fact]
    public void Decodes_a_framework_generated_rsa_csr()
    {
        using var key = RSA.Create(2048);

        var csr = CertificateSigningRequest.Decode(CreateRsaCsr(key));

        Assert.Equal(SignatureAlgorithm.Sha256WithRsa, csr.SignatureAlgorithm);
        Assert.Contains(csr.Subject.Components, c => c is { Oid: Oids.CommonName, Value: "Requester" });
        Assert.Equal(key.ExportSubjectPublicKeyInfo(), csr.SubjectPublicKeyInfo.Encode());
        Assert.Empty(csr.RequestedExtensions);
    }

    [Fact]
    public void Decodes_requested_extensions_from_an_ecdsa_csr()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var csr = CertificateSigningRequest.Decode(CreateEcdsaCsrWithSan(key));

        Assert.Equal(SignatureAlgorithm.EcdsaWithSha256, csr.SignatureAlgorithm);
        Assert.Equal(key.ExportSubjectPublicKeyInfo(), csr.SubjectPublicKeyInfo.Encode());
        var san = Assert.Single(csr.RequestedExtensions);
        Assert.Equal(Oids.SubjectAlternativeName, san.Oid);
    }

    [Fact]
    public void Rejects_a_csr_with_a_tampered_signature()
    {
        using var key = RSA.Create(2048);
        var der = CreateRsaCsr(key);
        der[^1] ^= 0x01; // flip a bit in the signature BIT STRING content

        Assert.Throws<CryptographicException>(() => CertificateSigningRequest.Decode(der));
    }

    [Fact]
    public void Rejects_a_csr_whose_request_info_was_altered()
    {
        using var key = RSA.Create(2048);
        var der = CreateRsaCsr(key);

        // Flip a bit inside the subject ("Requester" -> "Rfquester"): structure stays
        // valid DER, but the proof-of-possession must fail.
        var index = der.AsSpan().IndexOf("Requester"u8);
        Assert.True(index >= 0);
        der[index + 1] ^= 0x04;

        Assert.Throws<CryptographicException>(() => CertificateSigningRequest.Decode(der));
    }

    [Fact]
    public void Issues_a_chain_valid_certificate_from_a_csr()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caParameters = caKey.ExportParameters(includePrivateParameters: false);
        var caSpki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. caParameters.Q.X!, .. caParameters.Q.Y!]);
        var caName = DistinguishedName.Builder().Country("CH").CommonName("CSR Test CA").Build();
        var caSigner = new EcdsaSoftwareSigner(caKey);

        var caDer = new CertificateBuilder
        {
            Subject = caName,
            SubjectPublicKeyInfo = caSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: true, pathLengthConstraint: 0),
                CertificateExtensions.KeyUsage(KeyUsages.KeyCertSign | KeyUsages.CrlSign),
            ],
        }.SignSelfSigned(caSigner);

        using var requesterKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = CertificateSigningRequest.Decode(CreateEcdsaCsrWithSan(requesterKey));

        // CA policy: take subject and key from the CSR, honor only the SAN request.
        var leafDer = new CertificateBuilder
        {
            Subject = csr.Subject,
            SubjectPublicKeyInfo = csr.SubjectPublicKeyInfo,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddMonths(3),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: false),
                CertificateExtensions.KeyUsage(KeyUsages.DigitalSignature),
                .. csr.RequestedExtensions.Where(e => e.Oid == Oids.SubjectAlternativeName),
            ],
        }.Sign(caName, caSigner);

        using var caCertificate = X509CertificateLoader.LoadCertificate(caDer);
        using var leafCertificate = X509CertificateLoader.LoadCertificate(leafDer);

        Assert.Contains("CN=req.example.test", leafCertificate.Subject);
        Assert.Contains(leafCertificate.Extensions, e => e.Oid?.Value == Oids.SubjectAlternativeName);
        Assert.True(CertificateBuilderTests.ChainValidates(leafCertificate, caCertificate));
    }

    [Fact]
    public void Spki_decode_round_trips_rsa_and_ec()
    {
        using var rsa = RSA.Create(2048);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        foreach (var der in new[] { rsa.ExportSubjectPublicKeyInfo(), ecdsa.ExportSubjectPublicKeyInfo() })
        {
            Assert.Equal(der, SubjectPublicKeyInfo.Decode(der).Encode());
        }
    }

    [Fact]
    public void Unknown_signature_algorithm_oid_is_rejected()
    {
        Assert.Throws<NotSupportedException>(() => SignatureAlgorithmExtensions.FromOid("1.2.840.113549.1.1.4")); // md5WithRSA
    }
}
