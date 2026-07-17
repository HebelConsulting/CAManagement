using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using CAManagement.Tests.Unit;
using CAManagement.X509;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.Signing;

namespace CAManagement.Tests.Integration;

[Collection(SoftHsmCollection.Name)]
public sealed class CrlIssuanceTests(SoftHsmFixture fixture)
{
    [Fact]
    public void Hsm_backed_ca_signs_a_crl_that_verifies()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var label = $"crl-ca-{Guid.NewGuid():N}";
        var (publicKey, privateKey) = session.GenerateEcKeyPair(label);
        var caSpki = Pkcs11PublicKeyReader.Read(session, publicKey);
        var caSigner = new Pkcs11CertificateSigner(session, privateKey, SignatureAlgorithm.EcdsaWithSha256);
        var caName = DistinguishedName.Builder().Country("CH").CommonName($"CRL HSM CA {label}").Build();

        var caDer = new CertificateBuilder
        {
            Subject = caName,
            SubjectPublicKeyInfo = caSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: true),
                CertificateExtensions.KeyUsage(KeyUsages.KeyCertSign | KeyUsages.CrlSign),
                CertificateExtensions.SubjectKeyIdentifier(caSpki.ComputeKeyIdentifier()),
            ],
        }.SignSelfSigned(caSigner);

        var crlDer = new CrlBuilder
        {
            Issuer = caName,
            ThisUpdate = DateTimeOffset.UtcNow.AddMinutes(-5),
            NextUpdate = DateTimeOffset.UtcNow.AddDays(7),
            CrlNumber = 42,
            AuthorityKeyIdentifier = caSpki.ComputeKeyIdentifier(),
            RevokedCertificates =
            [
                new RevokedCertificate([0x0A, 0x0B, 0x0C], DateTimeOffset.UtcNow.AddDays(-1), RevocationReason.Superseded),
            ],
        }.Sign(caSigner);

        using var caCertificate = X509CertificateLoader.LoadCertificate(caDer);

        CertificateRevocationListBuilder.Load(crlDer, out BigInteger crlNumber);
        Assert.Equal(new BigInteger(42), crlNumber);
        Assert.True(CrlBuilderTests.CrlSignatureIsValid(crlDer, caCertificate),
            "HSM-signed CRL must verify against the CA certificate");
    }
}
