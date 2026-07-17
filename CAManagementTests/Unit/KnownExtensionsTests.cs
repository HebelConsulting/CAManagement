using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateAuthority;

namespace CAManagementTests.Unit;

public sealed class KnownExtensionsTests
{
    [Fact]
    public void Mixed_san_matches_framework_encoding()
    {
        var ours = CertificateExtensions.SubjectAlternativeName(
            GeneralName.Dns("host.example.test"),
            GeneralName.Email("ops@example.test"),
            GeneralName.Uri("https://example.test/info"),
            GeneralName.Ip("10.0.0.1"));

        var frameworkBuilder = new SubjectAlternativeNameBuilder();
        frameworkBuilder.AddDnsName("host.example.test");
        frameworkBuilder.AddEmailAddress("ops@example.test");
        frameworkBuilder.AddUri(new Uri("https://example.test/info"));
        frameworkBuilder.AddIpAddress(IPAddress.Parse("10.0.0.1"));

        Assert.Equal(frameworkBuilder.Build().RawData, ours.Value);
    }

    [Fact]
    public void Issuer_alternative_name_uses_its_own_oid_with_the_same_encoding()
    {
        var issuerAltName = CertificateExtensions.IssuerAlternativeName(GeneralName.Uri("https://ca.example.test"));
        var subjectAltName = CertificateExtensions.SubjectAlternativeName(GeneralName.Uri("https://ca.example.test"));

        Assert.Equal(Oids.IssuerAlternativeName, issuerAltName.Oid);
        Assert.Equal(subjectAltName.Value, issuerAltName.Value);
    }

    [Fact]
    public void Crl_distribution_points_encode_one_point_with_all_uris()
    {
        var extension = CertificateExtensions.CrlDistributionPoints(
            "http://crl1.example.test/ca.crl", "http://crl2.example.test/ca.crl");

        var points = new AsnReader(extension.Value, AsnEncodingRules.DER).ReadSequence();
        var point = points.ReadSequence();
        Assert.False(points.HasData); // exactly one DistributionPoint

        var fullName = point.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0))
            .ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        var uriTag = new Asn1Tag(TagClass.ContextSpecific, 6);
        Assert.Equal("http://crl1.example.test/ca.crl", fullName.ReadCharacterString(UniversalTagNumber.IA5String, uriTag));
        Assert.Equal("http://crl2.example.test/ca.crl", fullName.ReadCharacterString(UniversalTagNumber.IA5String, uriTag));
    }

    [Fact]
    public void Authority_info_access_lists_ocsp_and_ca_issuers()
    {
        var extension = CertificateExtensions.AuthorityInfoAccess(
            ocspUri: "http://ocsp.example.test", caIssuersUri: "http://ca.example.test/ca.crt");

        var descriptions = new AsnReader(extension.Value, AsnEncodingRules.DER).ReadSequence();
        var uriTag = new Asn1Tag(TagClass.ContextSpecific, 6);

        var ocsp = descriptions.ReadSequence();
        Assert.Equal(Oids.AccessMethodOcsp, ocsp.ReadObjectIdentifier());
        Assert.Equal("http://ocsp.example.test", ocsp.ReadCharacterString(UniversalTagNumber.IA5String, uriTag));

        var caIssuers = descriptions.ReadSequence();
        Assert.Equal(Oids.AccessMethodCaIssuers, caIssuers.ReadObjectIdentifier());

        Assert.Throws<ArgumentException>(() => CertificateExtensions.AuthorityInfoAccess());
    }

    [Fact]
    public void Certificate_policies_matches_golden_der()
    {
        var extension = CertificateExtensions.CertificatePolicies("2.5.29.32.0"); // anyPolicy

        // SEQUENCE { SEQUENCE { OID 2.5.29.32.0 } }
        Assert.Equal([0x30, 0x08, 0x30, 0x06, 0x06, 0x04, 0x55, 0x1D, 0x20, 0x00], extension.Value);
    }

    [Fact]
    public void Crl_additional_extensions_are_emitted()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuer = DistinguishedName.Parse("/CN=Additional Ext CA");

        var crlDer = new CrlBuilder
        {
            Issuer = issuer,
            ThisUpdate = DateTimeOffset.UtcNow,
            CrlNumber = 3,
            AdditionalExtensions = [CertificateExtensions.IssuerAlternativeName(GeneralName.Uri("https://ca.example.test"))],
        }.Sign(new EcdsaSoftwareSigner(caKey));

        CertificateRevocationListBuilder.Load(crlDer, out BigInteger crlNumber);
        Assert.Equal(new BigInteger(3), crlNumber);

        // Walk tbsCertList to crlExtensions [0] and collect the extension OIDs.
        var tbs = new AsnReader(crlDer, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        tbs.ReadEncodedValue(); // version
        tbs.ReadEncodedValue(); // signature
        tbs.ReadEncodedValue(); // issuer
        tbs.ReadEncodedValue(); // thisUpdate
        var extensions = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();

        var oids = new List<string>();
        while (extensions.HasData)
        {
            oids.Add(extensions.ReadSequence().ReadObjectIdentifier());
        }

        Assert.Equal([Oids.CrlNumber, Oids.IssuerAlternativeName], oids);
    }

    [Fact]
    public void Openssl_renders_a_certificate_carrying_all_new_extensions()
    {
        if (!File.Exists("/usr/bin/openssl"))
        {
            return;
        }

        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = caKey.ExportParameters(includePrivateParameters: false);
        var spki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. parameters.Q.X!, .. parameters.Q.Y!]);

        var der = new CertificateBuilder
        {
            Subject = DistinguishedName.Parse("/C=CH/CN=All Extensions"),
            SubjectPublicKeyInfo = spki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: true),
                CertificateExtensions.SubjectAlternativeName(
                    GeneralName.Dns("host.example.test"), GeneralName.Email("ops@example.test"),
                    GeneralName.Uri("https://example.test"), GeneralName.Ip("10.0.0.1")),
                CertificateExtensions.IssuerAlternativeName(GeneralName.Uri("https://ca.example.test")),
                CertificateExtensions.CrlDistributionPoints("http://crl.example.test/ca.crl"),
                CertificateExtensions.AuthorityInfoAccess("http://ocsp.example.test", "http://ca.example.test/ca.crt"),
                CertificateExtensions.CertificatePolicies("1.3.6.1.4.1.99999.1"),
            ],
        }.SignSelfSigned(new EcdsaSoftwareSigner(caKey));

        var path = Path.Combine(Path.GetTempPath(), $"allext-{Guid.NewGuid():N}.crt");
        try
        {
            File.WriteAllText(path, Pem.Encode("CERTIFICATE", der));

            var startInfo = new ProcessStartInfo("/usr/bin/openssl")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (var argument in (string[])["x509", "-in", path, "-noout", "-text"])
            {
                startInfo.ArgumentList.Add(argument);
            }

            using var process = Process.Start(startInfo)!;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, stderr.Result);

            var text = stdout.Result;
            Assert.Contains("DNS:host.example.test", text);
            Assert.Contains("email:ops@example.test", text);
            Assert.Contains("URI:https://example.test", text);
            Assert.Contains("IP Address:10.0.0.1", text);
            Assert.Contains("URI:https://ca.example.test", text);
            Assert.Contains("URI:http://crl.example.test/ca.crl", text);
            Assert.Contains("OCSP - URI:http://ocsp.example.test", text);
            Assert.Contains("CA Issuers - URI:http://ca.example.test/ca.crt", text);
            Assert.Contains("Policy: 1.3.6.1.4.1.99999.1", text);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
