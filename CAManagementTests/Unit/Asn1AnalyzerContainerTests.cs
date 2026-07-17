using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateAuthority.Analysis;

namespace CAManagementTests.Unit;

public sealed class Asn1AnalyzerContainerTests
{
    private static IEnumerable<Asn1Node> Flatten(Asn1Node node)
    {
        yield return node;
        foreach (var descendant in node.Children.SelectMany(Flatten))
        {
            yield return descendant;
        }
    }

    private static X509Certificate2 CreateSelfSigned(string commonName)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(new X500DistinguishedName($"CN={commonName}"), key, HashAlgorithmName.SHA256);

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    [Fact]
    public void Detects_and_annotates_a_pkcs12_container()
    {
        using var certificate = CreateSelfSigned("PFX Analyzer Test");
        var pfx = certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, "test-password");

        var document = Asn1Analyzer.Analyze(pfx);

        Assert.Equal(DocumentKind.Pkcs12, document.Kind);
        Assert.Equal("PFX", document.Root.Name);

        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n is { Name: "version", Value: "3" });
        Assert.Contains(nodes, n => n.Name == "authSafe");
        Assert.Contains(nodes, n => n.Name == "AuthenticatedSafe");
        Assert.Contains(nodes, n => n.Name == "macData");
        Assert.Contains(nodes, n => n.Name == "EncryptedPrivateKeyInfo"); // the shrouded key bag payload
    }

    [Fact]
    public void Pkcs12_exposes_pbes2_parameters_without_the_password()
    {
        using var certificate = CreateSelfSigned("PBES2 Params Test");
        var pfx = certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, "test-password");

        var nodes = Flatten(Asn1Analyzer.Analyze(pfx).Root).ToList();

        Assert.Contains(nodes, n => n.Name == "iterationCount");
        Assert.Contains(nodes, n => n.Name == "salt");
        Assert.Contains(nodes, n => n.Name == "encryptionScheme");
        Assert.Contains(nodes, n => n.Value?.Contains("aes256-CBC") == true);
    }

    [Fact]
    public void Detects_and_annotates_a_p7b_bundle()
    {
        using var first = CreateSelfSigned("P7B First");
        using var second = CreateSelfSigned("P7B Second");
        var collection = new X509Certificate2Collection { first, second };
        var p7b = collection.Export(X509ContentType.Pkcs7)!;

        var document = Asn1Analyzer.Analyze(p7b);

        Assert.Equal(DocumentKind.Cms, document.Kind);

        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n.Name == "SignedData");
        Assert.Contains(nodes, n => n.Name == "certificates");
        // The bundled certificates are fully annotated like standalone ones.
        Assert.Equal(2, nodes.Count(n => n.Name == "Certificate"));
        Assert.Contains(nodes, n => n.Name == "serialNumber");
    }

    [Fact]
    public void Pem_pkcs7_label_maps_to_cms()
    {
        using var certificate = CreateSelfSigned("PEM P7B");
        var p7b = new X509Certificate2Collection { certificate }.Export(X509ContentType.Pkcs7)!;

        var document = Asn1Analyzer.Analyze(CertificateAuthority.Pem.Encode("PKCS7", p7b));

        Assert.Equal(DocumentKind.Cms, document.Kind);
    }
}
