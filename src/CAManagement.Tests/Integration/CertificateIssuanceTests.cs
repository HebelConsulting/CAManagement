using System.Security.Cryptography.X509Certificates;
using CAManagement.Tests.Unit;
using CAManagement.X509;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.Signing;

namespace CAManagement.Tests.Integration;

/// <summary>
/// SPEC D6 end-to-end: a CA whose private key lives in SoftHSM issues
/// certificates that the .NET X.509 stack validates as a chain.
/// </summary>
[Collection(SoftHsmCollection.Name)]
public sealed class CertificateIssuanceTests(SoftHsmFixture fixture)
{
    [Theory]
    [InlineData(true)]  // ECDSA P-256 CA key in the HSM
    [InlineData(false)] // RSA-2048 CA key in the HSM
    public void Hsm_backed_ca_issues_a_chain_valid_certificate(bool useEcdsaCa)
    {
        if (useEcdsaCa && !fixture.SupportsEcdsaSha256()) { return; } // SoftHSM 2.5.0 lacks CKM_ECDSA_SHA256

        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var label = $"issuer-{(useEcdsaCa ? "ec" : "rsa")}-{Guid.NewGuid():N}";
        var (publicKey, privateKey) = useEcdsaCa
            ? session.GenerateEcKeyPair(label)
            : session.GenerateRsaKeyPair(label);

        var caSpki = Pkcs11PublicKeyReader.Read(session, publicKey);
        var caSigner = new Pkcs11CertificateSigner(session, privateKey,
            useEcdsaCa ? SignatureAlgorithm.EcdsaWithSha256 : SignatureAlgorithm.Sha256WithRsa);
        var caName = DistinguishedName.Builder()
            .Country("CH").Organization("Hebel Consulting").CommonName($"HSM Test CA {label}").Build();

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
                CertificateExtensions.SubjectKeyIdentifier(caSpki.ComputeKeyIdentifier()),
            ],
        }.SignSelfSigned(caSigner);

        // Leaf key also lives in the HSM; its public part goes into the leaf cert.
        var (leafPublicKey, _2) = session.GenerateEcKeyPair($"leaf-{Guid.NewGuid():N}");
        var leafSpki = Pkcs11PublicKeyReader.Read(session, leafPublicKey);

        var leafDer = new CertificateBuilder
        {
            Subject = DistinguishedName.Builder().CommonName("hsm-leaf.example.test").Build(),
            SubjectPublicKeyInfo = leafSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddMonths(3),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: false),
                CertificateExtensions.KeyUsage(KeyUsages.DigitalSignature),
                CertificateExtensions.SubjectKeyIdentifier(leafSpki.ComputeKeyIdentifier()),
                CertificateExtensions.AuthorityKeyIdentifier(caSpki.ComputeKeyIdentifier()),
            ],
        }.Sign(caName, caSigner);

        using var caCertificate = X509CertificateLoader.LoadCertificate(caDer);
        using var leafCertificate = X509CertificateLoader.LoadCertificate(leafDer);

        Assert.Equal(caCertificate.Subject, leafCertificate.Issuer);
        Assert.True(CertificateBuilderTests.ChainValidates(leafCertificate, caCertificate),
            "HSM-issued leaf must chain to the HSM-backed CA root");
    }

    [Fact]
    public void Hsm_backed_ca_issues_from_a_pkcs10_request()
    {
        if (!fixture.SupportsEcdsaSha256()) { return; } // EC CA; SoftHSM 2.5.0 lacks CKM_ECDSA_SHA256

        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var caLabel = $"csr-ca-{Guid.NewGuid():N}";
        var (caPublicKey, caPrivateKey) = session.GenerateEcKeyPair(caLabel);
        var caSpki = Pkcs11PublicKeyReader.Read(session, caPublicKey);
        var caSigner = new Pkcs11CertificateSigner(session, caPrivateKey, SignatureAlgorithm.EcdsaWithSha256);
        var caName = DistinguishedName.Builder().Country("CH").CommonName($"CSR HSM CA {caLabel}").Build();

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
                CertificateExtensions.SubjectKeyIdentifier(caSpki.ComputeKeyIdentifier()),
            ],
        }.SignSelfSigned(caSigner);

        // A requester (software key, e.g. a server) submits a PKCS#10 request.
        using var requesterKey = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var csrDer = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                new X500DistinguishedName("CN=csr.example.test"), requesterKey,
                System.Security.Cryptography.HashAlgorithmName.SHA256)
            .CreateSigningRequest();

        var csr = CertificateSigningRequest.Decode(csrDer);

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
                CertificateExtensions.AuthorityKeyIdentifier(caSpki.ComputeKeyIdentifier()),
            ],
        }.Sign(caName, caSigner);

        using var caCertificate = X509CertificateLoader.LoadCertificate(caDer);
        using var leafCertificate = X509CertificateLoader.LoadCertificate(leafDer);

        Assert.Contains("CN=csr.example.test", leafCertificate.Subject);
        Assert.True(CertificateBuilderTests.ChainValidates(leafCertificate, caCertificate),
            "certificate issued from a CSR must chain to the HSM-backed CA");
    }
}
