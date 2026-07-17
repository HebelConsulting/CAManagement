using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CAManagement.X509;
using CAManagement.X509.Ocsp;

namespace CAManagement.Tests.Unit;

public sealed class OcspTests : IDisposable
{
    private static readonly bool OpensslAvailable = File.Exists("/usr/bin/openssl");

    private readonly DirectoryInfo _workDir = Directory.CreateTempSubdirectory("ocsp-tests");

    private readonly ECDsa _caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly EcdsaSoftwareSigner _caSigner;
    private readonly SubjectPublicKeyInfo _caSpki;
    private readonly DistinguishedName _caName;
    private readonly byte[] _caDer;
    private readonly byte[] _leafDer;

    public OcspTests()
    {
        _caSigner = new EcdsaSoftwareSigner(_caKey);
        var parameters = _caKey.ExportParameters(includePrivateParameters: false);
        _caSpki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. parameters.Q.X!, .. parameters.Q.Y!]);
        _caName = DistinguishedName.Builder().Country("CH").CommonName("OCSP Test CA").Build();

        _caDer = new CertificateBuilder
        {
            Subject = _caName,
            SubjectPublicKeyInfo = _caSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: true),
                CertificateExtensions.KeyUsage(KeyUsages.KeyCertSign | KeyUsages.CrlSign | KeyUsages.DigitalSignature),
                CertificateExtensions.SubjectKeyIdentifier(_caSpki.ComputeKeyIdentifier()),
            ],
        }.SignSelfSigned(_caSigner);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafParameters = leafKey.ExportParameters(includePrivateParameters: false);
        var leafSpki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. leafParameters.Q.X!, .. leafParameters.Q.Y!]);

        _leafDer = new CertificateBuilder
        {
            Subject = DistinguishedName.Builder().CommonName("ocsp-leaf.example.test").Build(),
            SubjectPublicKeyInfo = leafSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddMonths(1),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: false),
                CertificateExtensions.AuthorityKeyIdentifier(_caSpki.ComputeKeyIdentifier()),
            ],
        }.Sign(_caName, _caSigner);
    }

    public void Dispose()
    {
        _caKey.Dispose();
        _workDir.Delete(recursive: true);
    }

    private string WritePem(string name, string label, byte[] der)
    {
        var path = Path.Combine(_workDir.FullName, name);
        File.WriteAllText(path, Pem.Encode(label, der));
        return path;
    }

    private byte[] LeafSerial()
    {
        using var leaf = X509CertificateLoader.LoadCertificate(_leafDer);
        return leaf.SerialNumberBytes.ToArray();
    }

    private OcspCertId LeafCertId() => OcspCertId.Create(HashAlgorithmName.SHA1, _caName.Encode(), _caSpki, LeafSerial());

    private byte[] OpensslRequest(bool nonce)
    {
        var caPath = WritePem("ca.pem", "CERTIFICATE", _caDer);
        var leafPath = WritePem("leaf.pem", "CERTIFICATE", _leafDer);
        var requestPath = Path.Combine(_workDir.FullName, $"req-{nonce}.der");

        string[] arguments = nonce
            ? ["ocsp", "-issuer", caPath, "-cert", leafPath, "-reqout", requestPath]
            : ["ocsp", "-issuer", caPath, "-cert", leafPath, "-reqout", requestPath, "-no_nonce"];
        var (exitCode, output) = RunOpenssl(arguments);
        Assert.True(exitCode == 0, $"openssl request generation failed: {output}");

        return File.ReadAllBytes(requestPath);
    }

    [Fact]
    public void Decodes_an_openssl_request_and_certid_matches_our_computation()
    {
        if (!OpensslAvailable)
        {
            return;
        }

        var request = OcspRequest.Decode(OpensslRequest(nonce: false));

        var certId = Assert.Single(request.Requests);
        Assert.Null(request.Nonce);
        Assert.True(LeafCertId().Matches(certId),
            "openssl's CertID must match the one computed from our issuer name/key");
    }

    [Fact]
    public void Extracts_the_nonce_from_an_openssl_request()
    {
        if (!OpensslAvailable)
        {
            return;
        }

        var request = OcspRequest.Decode(OpensslRequest(nonce: true));

        Assert.NotNull(request.Nonce);
        Assert.NotEmpty(request.Nonce);
    }

    [Theory]
    [InlineData(true)]  // good
    [InlineData(false)] // revoked
    public void Openssl_verifies_our_response(bool good)
    {
        if (!OpensslAvailable)
        {
            return;
        }

        // Nonce-free on purpose: LibreSSL 3.3.6's `ocsp` client rejects even its own
        // responder's nonce echo ("Nonce Verify error"), so the echo is asserted
        // byte-exactly in Nonce_is_echoed_byte_identically instead.
        var requestDer = OpensslRequest(nonce: false);
        var request = OcspRequest.Decode(requestDer);
        var certId = request.Requests.Single();

        var single = good
            ? OcspSingleResponse.Good(certId, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1))
            : OcspSingleResponse.Revoked(certId, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(-2),
                RevocationReason.KeyCompromise, DateTimeOffset.UtcNow.AddDays(1));

        var responseDer = new OcspResponseBuilder
        {
            ResponderPublicKey = _caSpki,
            ProducedAt = DateTimeOffset.UtcNow,
            Responses = [single],
            Nonce = request.Nonce,
            Certificates = [_caDer],
        }.Sign(_caSigner);

        var responsePath = Path.Combine(_workDir.FullName, "resp.der");
        File.WriteAllBytes(responsePath, responseDer);
        var requestPath = Path.Combine(_workDir.FullName, "req-verify.der");
        File.WriteAllBytes(requestPath, requestDer);

        var (exitCode, output) = RunOpenssl(["ocsp",
            "-respin", responsePath, "-reqin", requestPath,
            "-issuer", Path.Combine(_workDir.FullName, "ca.pem"),
            "-cert", Path.Combine(_workDir.FullName, "leaf.pem"),
            "-CAfile", Path.Combine(_workDir.FullName, "ca.pem")]);

        Assert.True(exitCode == 0, $"openssl response verification failed: {output}");
        Assert.Contains("Response verify OK", output);
        Assert.Contains(good ? "leaf.pem: good" : "leaf.pem: revoked", output);
        if (!good)
        {
            Assert.Contains("Reason: keyCompromise", output);
        }
    }

    [Fact]
    public void MatchesIssuer_distinguishes_our_ca_from_a_foreign_one()
    {
        var certId = LeafCertId();

        Assert.True(certId.MatchesIssuer(_caName.Encode(), _caSpki));

        using var foreignKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var foreignParameters = foreignKey.ExportParameters(includePrivateParameters: false);
        var foreignSpki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. foreignParameters.Q.X!, .. foreignParameters.Q.Y!]);
        var foreignName = DistinguishedName.Builder().CommonName("Foreign CA").Build();

        Assert.False(certId.MatchesIssuer(foreignName.Encode(), _caSpki)); // wrong name
        Assert.False(certId.MatchesIssuer(_caName.Encode(), foreignSpki)); // wrong key
    }

    [Fact]
    public void Nonce_is_echoed_byte_identically()
    {
        var nonce = new byte[] { 0x04, 0x10, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A };

        var responseDer = new OcspResponseBuilder
        {
            ResponderPublicKey = _caSpki,
            ProducedAt = DateTimeOffset.UtcNow,
            Responses = [OcspSingleResponse.Good(LeafCertId(), DateTimeOffset.UtcNow)],
            Nonce = nonce,
        }.Sign(_caSigner);

        // OCSPResponse -> BasicOCSPResponse -> tbsResponseData -> responseExtensions [1]
        var response = new AsnReader(responseDer, AsnEncodingRules.DER).ReadSequence();
        response.ReadEnumeratedValue<OcspResponseStatus>();
        var responseBytes = response.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
        responseBytes.ReadObjectIdentifier();
        var tbs = new AsnReader(responseBytes.ReadOctetString(), AsnEncodingRules.DER).ReadSequence().ReadSequence();

        tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2)); // responderID byKey
        tbs.ReadGeneralizedTime(); // producedAt
        tbs.ReadSequence(); // responses

        var extensions = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1)).ReadSequence();
        var extension = extensions.ReadSequence();
        Assert.Equal(Oids.OcspNonce, extension.ReadObjectIdentifier());
        Assert.Equal(nonce, extension.ReadOctetString());
    }

    [Fact]
    public void Response_signature_verifies_against_the_ca_key()
    {
        var responseDer = new OcspResponseBuilder
        {
            ResponderPublicKey = _caSpki,
            ProducedAt = DateTimeOffset.UtcNow,
            Responses = [OcspSingleResponse.Good(LeafCertId(), DateTimeOffset.UtcNow)],
        }.Sign(_caSigner);

        // OCSPResponse -> responseBytes -> BasicOCSPResponse
        var response = new AsnReader(responseDer, AsnEncodingRules.DER).ReadSequence();
        Assert.Equal(OcspResponseStatus.Successful, response.ReadEnumeratedValue<OcspResponseStatus>());
        var responseBytes = response.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
        Assert.Equal(Oids.OcspBasicResponse, responseBytes.ReadObjectIdentifier());
        var basic = new AsnReader(responseBytes.ReadOctetString(), AsnEncodingRules.DER).ReadSequence();

        var tbsResponseData = basic.PeekEncodedValue().ToArray();
        basic.ReadSequence();
        basic.ReadSequence(); // signatureAlgorithm
        var signature = basic.ReadBitString(out _);

        Assert.True(_caKey.VerifyData(tbsResponseData, signature, HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public void Error_response_is_a_bare_status()
    {
        var der = OcspResponseBuilder.CreateError(OcspResponseStatus.TryLater);

        var response = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
        Assert.Equal(OcspResponseStatus.TryLater, response.ReadEnumeratedValue<OcspResponseStatus>());
        Assert.False(response.HasData);

        Assert.Throws<ArgumentException>(() => OcspResponseBuilder.CreateError(OcspResponseStatus.Successful));
    }

    private static (int ExitCode, string Output) RunOpenssl(string[] arguments)
    {
        var startInfo = new ProcessStartInfo("/usr/bin/openssl")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();

        return (process.ExitCode, stdout.Result + stderr.Result);
    }
}
