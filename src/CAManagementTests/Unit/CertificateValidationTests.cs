using System.Diagnostics;
using System.Security.Cryptography;
using CertificateAuthority;
using CertificateAuthority.Analysis;

namespace CAManagementTests.Unit;

public sealed class CertificateValidationTests
{
    private sealed record TestCa(ECDsa Key, EcdsaSoftwareSigner Signer, SubjectPublicKeyInfo Spki, DistinguishedName Name, byte[] Der);

    private static TestCa CreateCa(string commonName, DistinguishedName? issuer = null,
        EcdsaSoftwareSigner? issuerSigner = null, int? pathLength = null)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new EcdsaSoftwareSigner(key);
        var parameters = key.ExportParameters(includePrivateParameters: false);
        var spki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. parameters.Q.X!, .. parameters.Q.Y!]);
        var name = DistinguishedName.Builder().CommonName(commonName).Build();

        var builder = new CertificateBuilder
        {
            Subject = name,
            SubjectPublicKeyInfo = spki,
            NotBefore = DateTimeOffset.UtcNow.AddDays(-60), // backdated so time-travel validations stay inside CA validity
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: true, pathLengthConstraint: pathLength),
                CertificateExtensions.KeyUsage(KeyUsages.KeyCertSign | KeyUsages.CrlSign),
                CertificateExtensions.SubjectKeyIdentifier(spki.ComputeKeyIdentifier()),
            ],
        };

        var der = issuer is null ? builder.SignSelfSigned(signer) : builder.Sign(issuer, issuerSigner!);

        return new TestCa(key, signer, spki, name, der);
    }

    private static byte[] IssueLeaf(TestCa issuer, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = key.ExportParameters(includePrivateParameters: false);
        var spki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. parameters.Q.X!, .. parameters.Q.Y!]);

        return new CertificateBuilder
        {
            Subject = DistinguishedName.Builder().CommonName("validation-leaf").Build(),
            SubjectPublicKeyInfo = spki,
            NotBefore = notBefore,
            NotAfter = notAfter,
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: false),
                CertificateExtensions.KeyUsage(KeyUsages.DigitalSignature),
                CertificateExtensions.AuthorityKeyIdentifier(issuer.Spki.ComputeKeyIdentifier()),
            ],
        }.Sign(issuer.Name, issuer.Signer);
    }

    [Fact]
    public void Three_level_chain_validates_with_intermediate_supplied()
    {
        var root = CreateCa("Validation Root", pathLength: 1);
        var intermediate = CreateCa("Validation Intermediate", root.Name, root.Signer, pathLength: 0);
        using var _1 = root.Key;
        using var _2 = intermediate.Key;
        var leaf = IssueLeaf(intermediate, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddMonths(1));

        var result = CertificateValidation.Validate(leaf, [root.Der], [intermediate.Der]);

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        Assert.Equal(3, result.ChainDer.Count); // leaf -> intermediate -> root
        Assert.Equal(leaf, result.ChainDer[0]);
        Assert.Equal(root.Der, result.ChainDer[^1]);
    }

    [Fact]
    public void Expired_leaf_fails_now_but_validates_at_a_time_it_was_valid()
    {
        var ca = CreateCa("Expiry CA");
        using var _ = ca.Key;
        var leaf = IssueLeaf(ca, DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(-1));

        var now = CertificateValidation.Validate(leaf, [ca.Der]);
        Assert.False(now.IsValid);
        Assert.Contains(now.Errors, error => error.Contains("NotTimeValid"));

        var backThen = CertificateValidation.Validate(leaf, [ca.Der], validationTime: DateTimeOffset.UtcNow.AddDays(-15));
        Assert.True(backThen.IsValid, string.Join("; ", backThen.Errors));
    }

    [Fact]
    public void Untrusted_root_fails()
    {
        var ca = CreateCa("Real CA");
        var other = CreateCa("Unrelated CA");
        using var _1 = ca.Key;
        using var _2 = other.Key;
        var leaf = IssueLeaf(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddMonths(1));

        var result = CertificateValidation.Validate(leaf, [other.Der]);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Pem_bundle_round_trips_through_DecodeAll()
    {
        var root = CreateCa("Bundle Root");
        var intermediate = CreateCa("Bundle Intermediate", root.Name, root.Signer);
        using var _1 = root.Key;
        using var _2 = intermediate.Key;

        var bundle = CertificateBundle.ToPemBundle([intermediate.Der, root.Der]);
        var blocks = Pem.DecodeAll(bundle);

        Assert.Equal(2, blocks.Count);
        Assert.Equal(intermediate.Der, blocks[0].Der);
        Assert.Equal(root.Der, blocks[1].Der);
    }

    [Fact]
    public void Own_pkcs7_bundle_is_detected_and_annotated_by_our_analyzer()
    {
        var root = CreateCa("P7B Own Root");
        var intermediate = CreateCa("P7B Own Intermediate", root.Name, root.Signer);
        using var _1 = root.Key;
        using var _2 = intermediate.Key;

        var p7b = CertificateBundle.ToPkcs7([intermediate.Der, root.Der]);
        var document = Asn1Analyzer.Analyze(p7b);

        Assert.Equal(DocumentKind.Cms, document.Kind);
        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n.Name == "SignedData");
        Assert.Equal(2, nodes.Count(n => n.Name == "Certificate"));
    }

    [Fact]
    public void Openssl_reads_our_pkcs7_bundle()
    {
        if (!File.Exists("/usr/bin/openssl"))
        {
            return;
        }

        var root = CreateCa("P7B Openssl Root");
        var intermediate = CreateCa("P7B Openssl Intermediate", root.Name, root.Signer);
        using var _1 = root.Key;
        using var _2 = intermediate.Key;

        var path = Path.Combine(Path.GetTempPath(), $"bundle-{Guid.NewGuid():N}.p7b");
        try
        {
            File.WriteAllBytes(path, CertificateBundle.ToPkcs7([intermediate.Der, root.Der]));

            var startInfo = new ProcessStartInfo("/usr/bin/openssl")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (var argument in (string[])["pkcs7", "-inform", "DER", "-in", path, "-print_certs", "-noout"])
            {
                startInfo.ArgumentList.Add(argument);
            }

            using var process = Process.Start(startInfo)!;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            process.WaitForExit();

            Assert.True(process.ExitCode == 0, stderr.Result);
            Assert.Contains("P7B Openssl Root", stdout.Result);
            Assert.Contains("P7B Openssl Intermediate", stdout.Result);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static IEnumerable<Asn1Node> Flatten(Asn1Node node)
    {
        yield return node;
        foreach (var descendant in node.Children.SelectMany(Flatten))
        {
            yield return descendant;
        }
    }
}
