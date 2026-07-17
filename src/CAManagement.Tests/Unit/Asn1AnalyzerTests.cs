using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CAManagement.X509;
using CAManagement.X509.Analysis;

namespace CAManagement.Tests.Unit;

public sealed class Asn1AnalyzerTests
{
    private static IEnumerable<Asn1Node> Flatten(Asn1Node node)
    {
        yield return node;
        foreach (var descendant in node.Children.SelectMany(Flatten))
        {
            yield return descendant;
        }
    }

    private static (byte[] Der, ECDsa Key) CreateSelfSignedCertificate()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(new X500DistinguishedName("CN=Analyzer Test"), key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        return (certificate.RawData, key);
    }

    [Fact]
    public void Detects_and_annotates_a_certificate()
    {
        var (der, key) = CreateSelfSignedCertificate();
        using var _ = key;

        var document = Asn1Analyzer.Analyze(der);

        Assert.Equal(DocumentKind.Certificate, document.Kind);
        Assert.Equal("Certificate", document.Root.Name);

        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n.Name == "serialNumber");
        Assert.Contains(nodes, n => n.Name == "notBefore" && n.TagName == "UTCTime");
        Assert.Contains(nodes, n => n.Name == "subjectPublicKey");
        Assert.Contains(nodes, n => n.Name == "basicConstraints"); // extension labeled by OID
        Assert.Contains(nodes, n => n is { Name: "version", Explanation: "v3" });
    }

    [Fact]
    public void Detects_a_pem_certificate_via_label()
    {
        var (der, key) = CreateSelfSignedCertificate();
        using var _ = key;

        var document = Asn1Analyzer.Analyze(Pem.Encode("CERTIFICATE", der));

        Assert.Equal(DocumentKind.Certificate, document.Kind);
    }

    [Fact]
    public void Detects_and_annotates_a_csr()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der = new CertificateRequest(new X500DistinguishedName("CN=req"), key, HashAlgorithmName.SHA256)
            .CreateSigningRequest();

        var document = Asn1Analyzer.Analyze(der);

        Assert.Equal(DocumentKind.CertificationRequest, document.Kind);
        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n.Name == "certificationRequestInfo");
        Assert.Contains(nodes, n => n.Name == "subject");
    }

    [Fact]
    public void Detects_and_annotates_a_crl()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var name = DistinguishedName.Builder().CommonName("CRL Analyzer CA").Build();

        var crlDer = new CrlBuilder
        {
            Issuer = name,
            ThisUpdate = DateTimeOffset.UtcNow,
            NextUpdate = DateTimeOffset.UtcNow.AddDays(7),
            CrlNumber = 5,
            RevokedCertificates = [new RevokedCertificate([0x42], DateTimeOffset.UtcNow, RevocationReason.KeyCompromise)],
        }.Sign(new EcdsaSoftwareSigner(key));

        var document = Asn1Analyzer.Analyze(crlDer);

        Assert.Equal(DocumentKind.CertificateList, document.Kind);
        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n.Name == "thisUpdate");
        Assert.Contains(nodes, n => n.Name == "userCertificate" && n.Value == "66"); // 0x42
        Assert.Contains(nodes, n => n.Name == "cRLReason");
        Assert.Contains(nodes, n => n.Name == "cRLNumber");
    }

    [Fact]
    public void Detects_public_and_private_keys()
    {
        using var rsa = RSA.Create(2048);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        Assert.Equal(DocumentKind.SubjectPublicKeyInfo, Asn1Analyzer.Analyze(rsa.ExportSubjectPublicKeyInfo()).Kind);
        Assert.Equal(DocumentKind.Pkcs8PrivateKey, Asn1Analyzer.Analyze(rsa.ExportPkcs8PrivateKey()).Kind);
        Assert.Equal(DocumentKind.RsaPrivateKey, Asn1Analyzer.Analyze(rsa.ExportRSAPrivateKey()).Kind);
        Assert.Equal(DocumentKind.EcPrivateKey, Asn1Analyzer.Analyze(ecdsa.ExportECPrivateKey()).Kind);
    }

    [Fact]
    public void Pkcs8_wrapped_rsa_key_is_annotated_through_the_octet_string()
    {
        using var rsa = RSA.Create(2048);

        var document = Asn1Analyzer.Analyze(rsa.ExportPkcs8PrivateKey());

        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n.Name == "RSAPrivateKey"); // encapsulated descent + annotation
        Assert.Contains(nodes, n => n.Name == "privateExponent");
    }

    [Fact]
    public void Unknown_der_still_yields_a_generic_tree()
    {
        // SEQUENCE { UTF8String "hi" } — valid DER, no known document shape.
        byte[] der = [0x30, 0x04, 0x0C, 0x02, 0x68, 0x69];

        var document = Asn1Analyzer.Analyze(der);

        Assert.Equal(DocumentKind.Unknown, document.Kind);
        Assert.Equal("SEQUENCE", document.Root.TagName);
        Assert.Equal("\"hi\"", document.Root.Children.Single().Value);
    }

    [Fact]
    public void Bundle_with_leading_comments_is_recognized_as_pem()
    {
        var (der, key) = CreateSelfSignedCertificate();
        using var _ = key;
        var bundle = $"## CA bundle comment\n## another line\n{Pem.Encode("CERTIFICATE", der)}\n";

        var document = Asn1Analyzer.Analyze(System.Text.Encoding.UTF8.GetBytes(bundle));

        Assert.Equal(DocumentKind.Certificate, document.Kind);
    }

    [Fact]
    public void DecodeAll_returns_every_block_of_a_bundle()
    {
        var (first, firstKey) = CreateSelfSignedCertificate();
        var (second, secondKey) = CreateSelfSignedCertificate();
        using var _1 = firstKey;
        using var _2 = secondKey;

        var bundle = $"## comment\n{Pem.Encode("CERTIFICATE", first)}\n## between\n{Pem.Encode("CERTIFICATE", second)}\n";

        var blocks = Pem.DecodeAll(bundle);

        Assert.Equal(2, blocks.Count);
        Assert.All(blocks, b => Assert.Equal("CERTIFICATE", b.Label));
        Assert.Equal(first, blocks[0].Der);
        Assert.Equal(second, blocks[1].Der);
    }

    [Fact]
    public void Offsets_and_lengths_describe_the_document()
    {
        var (der, key) = CreateSelfSignedCertificate();
        using var _ = key;

        var document = Asn1Analyzer.Analyze(der);

        Assert.Equal(0, document.Root.Offset);
        Assert.Equal(der.Length, document.Root.Length);
    }
}
