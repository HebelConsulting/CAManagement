using System.Security.Cryptography;
using CAManagement.X509;

namespace CAManagement.Tests.Unit;

/// <summary>
/// A decryption certificate's keyUsage is derived from the KEY, never named by the caller (#18).
/// </summary>
/// <remarks>
/// <para>
/// The defect: <c>caconsole issue</c> hard-coded <c>digitalSignature</c>, so a certificate issued for a
/// YubiKey PIV Key Management slot (9D) — whose entire purpose is to receive CMS <c>EnvelopedData</c> —
/// declared the one bit that does not apply to it.
/// </para>
/// <para>
/// <b>Why this is unit-tested at the derivation rather than end to end on an issued certificate.</b> The
/// wrong answer is invisible to anything that only checks a certificate parses, chains and decrypts:
/// measured on hardware, the signature-only certificate <i>decrypted a real CMS envelope</i>, because
/// neither <c>EnvelopedCms</c> nor the token enforces keyUsage. It fails only against a consumer that
/// checks — so the assertion has to be on the bits themselves.
/// </para>
/// </remarks>
public sealed class CertificatePurposeTests
{
    [Fact]
    public void An_EC_decryption_certificate_agrees_a_key_rather_than_transporting_one()
    {
        // ECDH: the content key is DERIVED, so `keyAgreement` is the bit, and `keyEncipherment` would be as
        // wrong as the signing default it replaces.
        var purpose = CertificatePurpose.For(CertificateProfile.KeyManagement, Oids.EcPublicKey);

        Assert.Equal(KeyUsages.KeyAgreement, purpose.KeyUsage);
        Assert.Equal([Oids.EmailProtection], purpose.ExtendedKeyUsages);
    }

    [Fact]
    public void An_RSA_decryption_certificate_transports_a_key()
    {
        var purpose = CertificatePurpose.For(CertificateProfile.KeyManagement, Oids.RsaEncryption);

        Assert.Equal(KeyUsages.KeyEncipherment, purpose.KeyUsage);
        Assert.Equal([Oids.EmailProtection], purpose.ExtendedKeyUsages);
    }

    [Fact]
    public void Neither_decryption_profile_declares_digitalSignature()
    {
        // Stated as its own assertion because it is the whole defect: the bit that must NOT be there. A test
        // asserting only the correct bit would still pass if the default were OR-ed in beside it.
        foreach (var algorithm in new[] { Oids.EcPublicKey, Oids.RsaEncryption })
        {
            var purpose = CertificatePurpose.For(CertificateProfile.KeyManagement, algorithm);

            Assert.False(purpose.KeyUsage.HasFlag(KeyUsages.DigitalSignature));
        }
    }

    [Fact]
    public void The_signing_profile_is_exactly_what_it_was_before_profiles_existed()
    {
        // The compatibility assertion. Every certificate this tool has issued so far carries this and no
        // extended key usage — an absent EKU means "any purpose", and narrowing it would silently invalidate
        // existing deployments for uses nobody declared.
        var purpose = CertificatePurpose.For(CertificateProfile.Signing, Oids.EcPublicKey);

        Assert.Equal(KeyUsages.DigitalSignature, purpose.KeyUsage);
        Assert.Empty(purpose.ExtendedKeyUsages);
    }

    [Fact]
    public void A_key_that_can_neither_agree_nor_transport_is_REFUSED_not_downgraded()
    {
        // Falling back to a signing certificate is the outcome being prevented, and it would arrive looking
        // like a success — an issued file, a zero exit code, and a card that decrypts nothing.
        var refusal = Assert.Throws<NotSupportedException>(() =>
            CertificatePurpose.For(CertificateProfile.KeyManagement, Oids.Sha256));

        Assert.Contains(Oids.Sha256, refusal.Message);
    }

    [Theory]
    [InlineData("signing", CertificateProfile.Signing)]
    [InlineData("key-management", CertificateProfile.KeyManagement)]
    [InlineData("KEY-MANAGEMENT", CertificateProfile.KeyManagement)]
    [InlineData("  key-management  ", CertificateProfile.KeyManagement)]
    [InlineData("keymanagement", CertificateProfile.KeyManagement)]
    public void The_option_value_is_spelled_the_way_an_option_value_is_spelled(string value, CertificateProfile expected) =>
        // Kebab-case, which the binder's own enum conversion would reject while accepting `KeyManagement` —
        // and every other option value in this tool is hyphenated.
        Assert.Equal(expected, CertificatePurpose.Parse(value));

    [Fact]
    public void An_unknown_profile_names_the_accepted_values()
    {
        // A refusal naming a CLR type teaches the reader nothing about what to type instead.
        var refusal = Assert.Throws<ArgumentException>(() => CertificatePurpose.Parse("decryption"));

        Assert.Contains("signing", refusal.Message);
        Assert.Contains("key-management", refusal.Message);
    }

    [Theory]
    [InlineData(Oids.EcPublicKey, System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.KeyAgreement)]
    [InlineData(Oids.RsaEncryption, System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.KeyEncipherment)]
    public void A_CONSUMER_reads_back_the_bit_we_wrote(
        string algorithm, System.Security.Cryptography.X509Certificates.X509KeyUsageFlags expected)
    {
        // Advertising and accepting are two lists, and this is the accepting side: the whole point of #18 is
        // what a client sees when it filters candidate certificates on "can this be an envelope recipient?".
        // So the extension is encoded by this codebase and decoded by the FRAMEWORK's parser, which is what
        // such a client would use — a test asserting our own enum against itself could not see a DER bug.
        var purpose = CertificatePurpose.For(CertificateProfile.KeyManagement, algorithm);
        var extension = CertificateExtensions.KeyUsage(purpose.KeyUsage);

        var asRead = new System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
            new System.Security.Cryptography.AsnEncodedData(extension.Oid, extension.Value),
            critical: extension.Critical);

        Assert.Equal(expected, asRead.KeyUsages);
    }

    [Fact]
    public void The_derivation_reads_the_algorithm_off_a_REAL_request_key()
    {
        // The seam between the two halves: `issue` reads `csr.SubjectPublicKeyInfo.AlgorithmOid`, so a
        // constant-only test would pass while that property answered something else. Built from framework
        // keys rather than fixtures, so it also pins that the OIDs this switch matches are the OIDs a real
        // SPKI carries.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecSpki = SubjectPublicKeyInfo.Decode(ec.ExportSubjectPublicKeyInfo());

        using var rsa = RSA.Create(2048);
        var rsaSpki = SubjectPublicKeyInfo.Decode(rsa.ExportSubjectPublicKeyInfo());

        Assert.Equal(
            KeyUsages.KeyAgreement,
            CertificatePurpose.For(CertificateProfile.KeyManagement, ecSpki.AlgorithmOid).KeyUsage);
        Assert.Equal(
            KeyUsages.KeyEncipherment,
            CertificatePurpose.For(CertificateProfile.KeyManagement, rsaSpki.AlgorithmOid).KeyUsage);
    }
}
