using System.Formats.Asn1;
using System.Security.Cryptography;
using CAManagement.X509;
using CAManagement.X509.Analysis;
using CAManagement.X509.Ocsp;

namespace CAManagement.Tests.Unit;

public sealed class Asn1AnalyzerOcspTests
{
    private static IEnumerable<Asn1Node> Flatten(Asn1Node node)
    {
        yield return node;
        foreach (var descendant in node.Children.SelectMany(Flatten))
        {
            yield return descendant;
        }
    }

    private static byte[] MinimalRequest()
    {
        // OCSPRequest { tbsRequest { requestList { Request { CertID } } } }
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.PushSequence();
        writer.PushSequence();
        writer.PushSequence(); // CertID
        writer.PushSequence();
        writer.WriteObjectIdentifier(Oids.Sha1);
        writer.WriteNull();
        writer.PopSequence();
        writer.WriteOctetString(new byte[20]);
        writer.WriteOctetString(new byte[20]);
        writer.WriteIntegerUnsigned([0x12, 0x34]);
        writer.PopSequence();
        writer.PopSequence();
        writer.PopSequence();
        writer.PopSequence();
        writer.PopSequence();

        return writer.Encode();
    }

    [Fact]
    public void Detects_and_annotates_an_ocsp_request()
    {
        var document = Asn1Analyzer.Analyze(MinimalRequest());

        Assert.Equal(DocumentKind.OcspRequest, document.Kind);
        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n.Name == "requestList");
        Assert.Contains(nodes, n => n.Name == "CertID");
        Assert.Contains(nodes, n => n.Name == "issuerKeyHash");
        Assert.Contains(nodes, n => n is { Name: "serialNumber", Value: "4660" }); // 0x1234
    }

    [Fact]
    public void Detects_and_annotates_a_signed_response()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = caKey.ExportParameters(includePrivateParameters: false);
        var caSpki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. parameters.Q.X!, .. parameters.Q.Y!]);
        var caName = DistinguishedName.Parse("/CN=OCSP Analyzer CA");

        var caDer = new CertificateBuilder
        {
            Subject = caName,
            SubjectPublicKeyInfo = caSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
            Extensions = [CertificateExtensions.BasicConstraints(isCa: true)],
        }.SignSelfSigned(new EcdsaSoftwareSigner(caKey));

        var certId = OcspCertId.Create(HashAlgorithmName.SHA1, caName.Encode(), caSpki, [0x0A, 0x0B]);
        var responseDer = new OcspResponseBuilder
        {
            ResponderPublicKey = caSpki,
            ProducedAt = DateTimeOffset.UtcNow,
            Responses =
            [
                OcspSingleResponse.Revoked(certId, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(-1),
                    RevocationReason.KeyCompromise, DateTimeOffset.UtcNow.AddDays(1)),
            ],
            Nonce = [0x04, 0x02, 0xAB, 0xCD],
            Certificates = [caDer],
        }.Sign(new EcdsaSoftwareSigner(caKey));

        var document = Asn1Analyzer.Analyze(responseDer);

        Assert.Equal(DocumentKind.OcspResponse, document.Kind);
        var nodes = Flatten(document.Root).ToList();

        Assert.Contains(nodes, n => n is { Name: "responseStatus", Explanation: "successful" });
        Assert.Contains(nodes, n => n.Name == "BasicOCSPResponse");
        Assert.Contains(nodes, n => n is { Name: "responderID" } && n.Explanation!.Contains("byKey"));
        Assert.Contains(nodes, n => n.Name == "producedAt");
        Assert.Contains(nodes, n => n is { Name: "certStatus" } && n.Explanation!.Contains("revoked"));
        Assert.Contains(nodes, n => n.Name == "revocationTime");
        Assert.Contains(nodes, n => n.Name == "nextUpdate");
        Assert.Contains(nodes, n => n.Name == "id-pkix-ocsp-nonce"); // extension labeled by OID
        Assert.Contains(nodes, n => n.Name == "Certificate"); // embedded CA cert fully annotated
    }

    [Fact]
    public void Error_response_shows_the_status_meaning()
    {
        var document = Asn1Analyzer.Analyze(OcspResponseBuilder.CreateError(OcspResponseStatus.TryLater));

        Assert.Equal(DocumentKind.OcspResponse, document.Kind);
        Assert.Contains(Flatten(document.Root), n => n is { Name: "responseStatus", Explanation: "tryLater" });
    }
}
