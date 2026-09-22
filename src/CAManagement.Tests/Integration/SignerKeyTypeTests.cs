using CAManagement.X509;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Signing;

namespace CAManagement.Tests.Integration;

/// <summary>
/// Issue #9: asking SoftHSM to sign with a mechanism the key cannot serve is a PROCESS CRASH, not a
/// CKR error (RSA_size(NULL) under C_Sign), so the signer must refuse the mismatch before any PKCS#11
/// call — and offer a shape that cannot mismatch at all.
/// </summary>
[Collection(SoftHsmCollection.Name)]
public sealed class SignerKeyTypeTests(SoftHsmFixture fixture)
{
    [Fact]
    public void An_rsa_algorithm_on_an_ec_key_is_refused_at_construction()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var (_, privateKey) = session.GenerateEcKeyPair($"mismatch-ec-{Guid.NewGuid():N}");

        var thrown = Assert.Throws<ArgumentException>(
            () => new Pkcs11CertificateSigner(session, privateKey, SignatureAlgorithm.Sha256WithRsa));

        // The message must carry both sides of the disagreement and name the safe alternative —
        // it replaces a crash report, so it has to be the whole diagnosis. (CKK_EC and CKK_ECDSA
        // alias the same value and ToString may pick either spelling; assert the shared prefix.)
        Assert.Contains(nameof(CK_KEY_TYPE.CKK_EC), thrown.Message);
        Assert.Contains(nameof(SignatureAlgorithm.Sha256WithRsa), thrown.Message);
        Assert.Contains(nameof(Pkcs11CertificateSigner.ForKey), thrown.Message);
    }

    [Fact]
    public void An_ecdsa_algorithm_on_an_rsa_key_is_refused_at_construction()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var (_, privateKey) = session.GenerateRsaKeyPair($"mismatch-rsa-{Guid.NewGuid():N}");

        Assert.Throws<ArgumentException>(
            () => new Pkcs11CertificateSigner(session, privateKey, SignatureAlgorithm.EcdsaWithSha256));
    }

    [Fact]
    public void ForKey_derives_rsa_and_the_signature_verifies()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, privateKey) = session.GenerateRsaKeyPair($"forkey-rsa-{Guid.NewGuid():N}");
        var signer = Pkcs11CertificateSigner.ForKey(session, privateKey);

        Assert.Equal(SignatureAlgorithm.Sha256WithRsa, signer.SignatureAlgorithm);
        var data = new byte[] { 1, 2, 3, 4 };
        Assert.True(session.Verify(CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS, data, signer.Sign(data), publicKey));
    }

    [Fact]
    public void ForKey_derives_ecdsa_and_signs()
    {
        if (!fixture.SupportsEcdsaSha256()) { return; } // SoftHSM 2.5.0 lacks CKM_ECDSA_SHA256

        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var (_, privateKey) = session.GenerateEcKeyPair($"forkey-ec-{Guid.NewGuid():N}");
        var signer = Pkcs11CertificateSigner.ForKey(session, privateKey);

        Assert.Equal(SignatureAlgorithm.EcdsaWithSha256, signer.SignatureAlgorithm);
        // The signer DER-encodes ECDSA output; non-empty DER SEQUENCE is enough here — chain-level
        // validity of ECDSA signatures is CertificateIssuanceTests' job.
        var signature = signer.Sign([1, 2, 3, 4]);
        Assert.NotEmpty(signature);
        Assert.Equal(0x30, signature[0]);
    }
}
