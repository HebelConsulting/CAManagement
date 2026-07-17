using System.Diagnostics;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateAuthority;

namespace CAManagementTests.Unit;

public sealed class CrlBuilderTests
{
    private static readonly DistinguishedName CaName = DistinguishedName.Builder()
        .Country("CH").CommonName("CRL Test CA").Build();

    private static readonly byte[] SerialOne = [0x11, 0x22, 0x33, 0x44];
    private static readonly byte[] SerialTwo = [0x55, 0x66, 0x77, 0x88];

    private static (byte[] CrlDer, X509Certificate2 CaCertificate) BuildCaAndCrl(ECDsa caKey)
    {
        var parameters = caKey.ExportParameters(includePrivateParameters: false);
        var caSpki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, [0x04, .. parameters.Q.X!, .. parameters.Q.Y!]);
        var signer = new EcdsaSoftwareSigner(caKey);

        var caDer = new CertificateBuilder
        {
            Subject = CaName,
            SubjectPublicKeyInfo = caSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: true),
                CertificateExtensions.KeyUsage(KeyUsages.KeyCertSign | KeyUsages.CrlSign),
                CertificateExtensions.SubjectKeyIdentifier(caSpki.ComputeKeyIdentifier()),
            ],
        }.SignSelfSigned(signer);

        var crlDer = new CrlBuilder
        {
            Issuer = CaName,
            ThisUpdate = DateTimeOffset.UtcNow.AddMinutes(-5),
            NextUpdate = DateTimeOffset.UtcNow.AddDays(7),
            CrlNumber = 7,
            AuthorityKeyIdentifier = caSpki.ComputeKeyIdentifier(),
            RevokedCertificates =
            [
                new RevokedCertificate(SerialOne, DateTimeOffset.UtcNow.AddDays(-1), RevocationReason.KeyCompromise),
                new RevokedCertificate(SerialTwo, DateTimeOffset.UtcNow.AddHours(-2)),
            ],
        }.Sign(signer);

        return (crlDer, X509CertificateLoader.LoadCertificate(caDer));
    }

    [Fact]
    public void Framework_loads_the_crl_and_reports_the_crl_number()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (crlDer, caCertificate) = BuildCaAndCrl(caKey);
        using var _ = caCertificate;

        CertificateRevocationListBuilder.Load(crlDer, out BigInteger crlNumber);

        Assert.Equal(new BigInteger(7), crlNumber);
    }

    [Fact]
    public void Signature_verifies_with_the_ca_key_and_tampering_breaks_it()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (crlDer, caCertificate) = BuildCaAndCrl(caKey);
        using var _ = caCertificate;

        Assert.True(CrlSignatureIsValid(crlDer, caCertificate));

        var tampered = (byte[])crlDer.Clone();
        tampered[^1] ^= 0x01;
        Assert.False(CrlSignatureIsValid(tampered, caCertificate));
    }

    [Fact]
    public void Entries_carry_serials_and_reason_codes()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (crlDer, caCertificate) = BuildCaAndCrl(caKey);
        using var _ = caCertificate;

        var entries = ReadEntries(crlDer);

        Assert.Equal(2, entries.Count);
        Assert.Equal(SerialOne, entries[0].Serial);
        Assert.Equal(RevocationReason.KeyCompromise, entries[0].Reason);
        Assert.Equal(SerialTwo, entries[1].Serial);
        Assert.Null(entries[1].Reason);
    }

    [Fact]
    public void Empty_crl_is_valid_and_loads()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = caKey.ExportParameters(includePrivateParameters: false);
        var signer = new EcdsaSoftwareSigner(caKey);

        var crlDer = new CrlBuilder
        {
            Issuer = CaName,
            ThisUpdate = DateTimeOffset.UtcNow,
            NextUpdate = DateTimeOffset.UtcNow.AddDays(7),
            CrlNumber = 1,
        }.Sign(signer);

        CertificateRevocationListBuilder.Load(crlDer, out BigInteger crlNumber);
        Assert.Equal(BigInteger.One, crlNumber);
        Assert.Empty(ReadEntries(crlDer));
    }

    [Fact]
    public void Rejects_next_update_before_this_update()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var builder = new CrlBuilder
        {
            Issuer = CaName,
            ThisUpdate = DateTimeOffset.UtcNow,
            NextUpdate = DateTimeOffset.UtcNow.AddDays(-1),
            CrlNumber = 1,
        };

        Assert.Throws<InvalidOperationException>(() => builder.Sign(new EcdsaSoftwareSigner(caKey)));
    }

    [Fact]
    public void Openssl_accepts_the_crl_when_available()
    {
        if (!File.Exists("/usr/bin/openssl"))
        {
            return; // independent verifier not installed; covered by the other tests
        }

        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (crlDer, caCertificate) = BuildCaAndCrl(caKey);
        using var _ = caCertificate;

        var directory = Directory.CreateTempSubdirectory("crl-openssl");
        try
        {
            var crlPath = Path.Combine(directory.FullName, "crl.der");
            var caPath = Path.Combine(directory.FullName, "ca.pem");
            File.WriteAllBytes(crlPath, crlDer);
            File.WriteAllText(caPath, caCertificate.ExportCertificatePem());

            var (textExit, textOutput) = RunOpenssl($"crl -inform DER -in {crlPath} -noout -text");
            Assert.Equal(0, textExit);
            Assert.Contains("11223344", textOutput, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Key Compromise", textOutput);

            var (verifyExit, verifyOutput) = RunOpenssl($"crl -inform DER -in {crlPath} -CAfile {caPath} -noout");
            Assert.Equal(0, verifyExit);
            Assert.Contains("verify OK", verifyOutput);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static (int ExitCode, string Output) RunOpenssl(string arguments)
    {
        var startInfo = new ProcessStartInfo("/usr/bin/openssl", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        using var process = Process.Start(startInfo)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();

        return (process.ExitCode, stdout.Result + stderr.Result);
    }

    internal static bool CrlSignatureIsValid(byte[] crlDer, X509Certificate2 issuer)
    {
        var reader = new AsnReader(crlDer, AsnEncodingRules.DER).ReadSequence();
        var tbsCertList = reader.PeekEncodedValue().ToArray();
        reader.ReadSequence();
        var algorithm = SignatureAlgorithmExtensions.FromOid(reader.ReadSequence().ReadObjectIdentifier());
        var signature = reader.ReadBitString(out _);

        if (algorithm.IsEcdsa())
        {
            using var ecdsa = issuer.GetECDsaPublicKey()!;
            return ecdsa.VerifyData(tbsCertList, signature, algorithm.HashAlgorithmName(), DSASignatureFormat.Rfc3279DerSequence);
        }

        using var rsa = issuer.GetRSAPublicKey()!;
        return rsa.VerifyData(tbsCertList, signature, algorithm.HashAlgorithmName(), RSASignaturePadding.Pkcs1);
    }

    private static List<(byte[] Serial, RevocationReason? Reason)> ReadEntries(byte[] crlDer)
    {
        var tbs = new AsnReader(crlDer, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        tbs.ReadInteger(); // version
        tbs.ReadSequence(); // signature algorithm
        tbs.ReadSequence(); // issuer
        tbs.ReadUtcTime(); // thisUpdate
        tbs.ReadUtcTime(); // nextUpdate

        var entries = new List<(byte[], RevocationReason?)>();

        if (tbs.HasData && tbs.PeekTag() == Asn1Tag.Sequence)
        {
            var revoked = tbs.ReadSequence();
            while (revoked.HasData)
            {
                var entry = revoked.ReadSequence();
                var serial = entry.ReadIntegerBytes().ToArray();
                entry.ReadUtcTime();

                RevocationReason? reason = null;
                if (entry.HasData)
                {
                    var extension = entry.ReadSequence().ReadSequence();
                    Assert.Equal(Oids.CrlReasonCode, extension.ReadObjectIdentifier());
                    reason = new AsnReader(extension.ReadOctetString(), AsnEncodingRules.DER)
                        .ReadEnumeratedValue<RevocationReason>();
                }

                entries.Add((serial, reason));
            }
        }

        return entries;
    }
}
