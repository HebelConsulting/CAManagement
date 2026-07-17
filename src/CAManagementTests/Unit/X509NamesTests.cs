using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateAuthority;

namespace CAManagementTests.Unit;

public sealed class X509NamesTests
{
    private static readonly DistinguishedName CaName = DistinguishedName.Parse("/C=CH/O=Hebel Consulting/CN=Names CA");

    private sealed record Fixture(byte[] CaDer, byte[] LeafDer, byte[] CsrDer, byte[] CrlDer);

    private static Fixture Create()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new EcdsaSoftwareSigner(caKey);
        var parameters = caKey.ExportParameters(includePrivateParameters: false);
        var caSpki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. parameters.Q.X!, .. parameters.Q.Y!]);

        var caDer = new CertificateBuilder
        {
            Subject = CaName,
            SubjectPublicKeyInfo = caSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
            Extensions = [CertificateExtensions.BasicConstraints(isCa: true)],
        }.SignSelfSigned(signer);

        var leafDer = new CertificateBuilder
        {
            Subject = DistinguishedName.Parse("/CN=names-leaf.example.test"),
            SubjectPublicKeyInfo = caSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddMonths(1),
        }.Sign(CaName, signer);

        using var requesterKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csrDer = new CertificateRequest(
            new X500DistinguishedName("CN=names-requester"), requesterKey, HashAlgorithmName.SHA256).CreateSigningRequest();

        var crlDer = new CrlBuilder
        {
            Issuer = CaName,
            ThisUpdate = DateTimeOffset.UtcNow,
            CrlNumber = 1,
        }.Sign(signer);

        return new Fixture(caDer, leafDer, csrDer, crlDer);
    }

    [Fact]
    public void Extracts_subject_and_issuer_from_certificates_in_der_and_pem()
    {
        var fixture = Create();

        Assert.Equal(CaName.Encode(), X509Names.SubjectOf(fixture.CaDer).Encode());
        Assert.Equal(CaName.Encode(), X509Names.IssuerOf(fixture.LeafDer).Encode());
        Assert.Equal("CN=names-leaf.example.test", X509Names.SubjectOf(fixture.LeafDer).ToString());

        var pem = System.Text.Encoding.UTF8.GetBytes("# comment\n" + Pem.Encode("CERTIFICATE", fixture.CaDer));
        Assert.Equal(CaName.Encode(), X509Names.SubjectOf(pem).Encode());
    }

    [Fact]
    public void Extracts_csr_subject_and_crl_issuer()
    {
        var fixture = Create();

        Assert.Contains(X509Names.SubjectOf(fixture.CsrDer).Components,
            c => c is { Oid: Oids.CommonName, Value: "names-requester" });
        Assert.Equal(CaName.Encode(), X509Names.IssuerOf(fixture.CrlDer).Encode());
    }

    [Fact]
    public void Extracted_issuer_is_byte_identical_for_crl_building()
    {
        // The exact use case: take the CA certificate, extract its subject as the
        // CRL issuer — bytes must equal the certificate's subject encoding.
        var fixture = Create();
        using var caCertificate = X509CertificateLoader.LoadCertificate(fixture.CaDer);

        var issuer = X509Names.SubjectOf(fixture.CaDer);

        Assert.Equal(caCertificate.SubjectName.RawData, issuer.Encode());
    }

    [Fact]
    public void Framework_created_certificate_subject_extracts_byte_identically()
    {
        // Framework DNs use different string types than our defaults — fidelity check.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=Foreign Encoding, O=Example"), key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        Assert.Equal(certificate.SubjectName.RawData, X509Names.SubjectOf(certificate.RawData).Encode());
    }

    [Fact]
    public void Wrong_document_kinds_are_rejected_with_clear_errors()
    {
        var fixture = Create();
        using var rsa = RSA.Create(2048);

        Assert.Throws<NotSupportedException>(() => X509Names.IssuerOf(fixture.CsrDer)); // CSRs have no issuer
        Assert.Throws<NotSupportedException>(() => X509Names.SubjectOf(fixture.CrlDer)); // CRLs have no subject
        Assert.Throws<NotSupportedException>(() => X509Names.SubjectOf(rsa.ExportSubjectPublicKeyInfo()));
    }
}
