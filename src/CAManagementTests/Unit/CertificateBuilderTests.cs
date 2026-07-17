using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateAuthority;

namespace CAManagementTests.Unit;

public sealed class CertificateBuilderTests
{
    private static readonly DistinguishedName CaName = DistinguishedName.Builder()
        .Country("CH").Organization("Hebel Consulting").CommonName("Unit Test CA").Build();

    private static SubjectPublicKeyInfo SpkiOf(ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        return SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. parameters.Q.X!, .. parameters.Q.Y!]);
    }

    private static byte[] SelfSignedCa(ECDsa caKey, SubjectPublicKeyInfo caSpki) => new CertificateBuilder
    {
        Subject = CaName,
        SubjectPublicKeyInfo = caSpki,
        NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
        NotAfter = DateTimeOffset.UtcNow.AddYears(1),
        Extensions =
        [
            CertificateExtensions.BasicConstraints(isCa: true, pathLengthConstraint: 0),
            CertificateExtensions.KeyUsage(KeyUsages.KeyCertSign | KeyUsages.CrlSign),
            CertificateExtensions.SubjectKeyIdentifier(caSpki.ComputeKeyIdentifier()),
        ],
    }.SignSelfSigned(new EcdsaSoftwareSigner(caKey));

    [Fact]
    public void Framework_loads_a_self_signed_certificate_with_expected_fields()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var serial = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

        var der = new CertificateBuilder
        {
            Subject = CaName,
            SubjectPublicKeyInfo = SpkiOf(caKey),
            NotBefore = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            NotAfter = new DateTimeOffset(2036, 1, 1, 0, 0, 0, TimeSpan.Zero),
            SerialNumber = serial,
            Extensions = [CertificateExtensions.BasicConstraints(isCa: true)],
        }.SignSelfSigned(new EcdsaSoftwareSigner(caKey));

        using var certificate = X509CertificateLoader.LoadCertificate(der);

        Assert.Equal(3, certificate.Version);
        Assert.Equal("0123456789ABCDEF", certificate.SerialNumber);
        Assert.Contains("CN=Unit Test CA", certificate.Subject);
        Assert.Equal(certificate.Subject, certificate.Issuer);
        Assert.Equal(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), certificate.NotBefore.ToUniversalTime());
        Assert.Equal(new DateTime(2036, 1, 1, 0, 0, 0, DateTimeKind.Utc), certificate.NotAfter.ToUniversalTime());

        var basicConstraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        Assert.True(basicConstraints.CertificateAuthority);
        Assert.True(basicConstraints.Critical);
    }

    [Theory]
    [InlineData(true)]  // ECDSA CA
    [InlineData(false)] // RSA CA
    public void Issued_certificate_chains_to_the_ca_root(bool useEcdsaCa)
    {
        using var ecdsaCaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsaCaKey = RSA.Create(2048);
        var caRsaParameters = rsaCaKey.ExportParameters(includePrivateParameters: false);

        ICertificateSigner caSigner = useEcdsaCa
            ? new EcdsaSoftwareSigner(ecdsaCaKey)
            : new RsaSoftwareSigner(rsaCaKey);
        var caSpki = useEcdsaCa
            ? SpkiOf(ecdsaCaKey)
            : SubjectPublicKeyInfo.FromRsa(caRsaParameters.Modulus!, caRsaParameters.Exponent!);

        var caDer = new CertificateBuilder
        {
            Subject = CaName,
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

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafSpki = SpkiOf(leafKey);

        var leafDer = new CertificateBuilder
        {
            Subject = DistinguishedName.Builder().CommonName("leaf.example.test").Build(),
            SubjectPublicKeyInfo = leafSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddMonths(3),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: false),
                CertificateExtensions.KeyUsage(KeyUsages.DigitalSignature),
                CertificateExtensions.SubjectKeyIdentifier(leafSpki.ComputeKeyIdentifier()),
                CertificateExtensions.AuthorityKeyIdentifier(caSpki.ComputeKeyIdentifier()),
                CertificateExtensions.ExtendedKeyUsage(Oids.ServerAuthentication),
                CertificateExtensions.SubjectAlternativeDnsNames("leaf.example.test"),
            ],
        }.Sign(CaName, caSigner);

        using var caCertificate = X509CertificateLoader.LoadCertificate(caDer);
        using var leafCertificate = X509CertificateLoader.LoadCertificate(leafDer);

        Assert.True(ChainValidates(leafCertificate, caCertificate), "leaf must chain to the CA root");
    }

    [Fact]
    public void Default_serial_is_random_and_positive()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var builder = new CertificateBuilder
        {
            Subject = CaName,
            SubjectPublicKeyInfo = SpkiOf(caKey),
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
        };
        var signer = new EcdsaSoftwareSigner(caKey);

        using var first = X509CertificateLoader.LoadCertificate(builder.SignSelfSigned(signer));
        using var second = X509CertificateLoader.LoadCertificate(builder.SignSelfSigned(signer));

        Assert.NotEqual(first.SerialNumber, second.SerialNumber);
        Assert.True(first.SerialNumberBytes.Span[0] < 0x80, "serial must be a positive INTEGER");
    }

    [Fact]
    public void Rejects_inverted_validity()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var builder = new CertificateBuilder
        {
            Subject = CaName,
            SubjectPublicKeyInfo = SpkiOf(caKey),
            NotBefore = DateTimeOffset.UtcNow,
            NotAfter = DateTimeOffset.UtcNow.AddDays(-1),
        };

        Assert.Throws<InvalidOperationException>(() => builder.SignSelfSigned(new EcdsaSoftwareSigner(caKey)));
    }

    internal static bool ChainValidates(X509Certificate2 leaf, X509Certificate2 root) =>
        CertificateValidation.Validate(leaf.RawData, [root.RawData]).IsValid;
}
