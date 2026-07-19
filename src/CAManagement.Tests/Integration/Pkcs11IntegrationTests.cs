using System.Text;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Extensions;

namespace CAManagement.Tests.Integration;

[Collection(SoftHsmCollection.Name)]
public sealed class Pkcs11IntegrationTests(SoftHsmFixture fixture)
{
    private const CK_MECHANISM_TYPE SignMechanism = CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS;

    [Fact]
    public void Loads_module_and_reports_cryptoki_version()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());

        // SoftHSM 2.7 advertises a 3.x function-list header while implementing 2.40.
        Assert.True(library.CryptokiVersion.Major >= 2);
    }

    [Fact]
    public void Opens_session_on_the_labelled_token()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());

        using var session = library.OpenSession();

        Assert.NotEqual((NativeULong)0, session.Handle);
    }

    [Fact]
    public void Generates_rsa_keypair_and_round_trips_a_signature()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, privateKey) = session.GenerateRsaKeyPair($"rt-{Guid.NewGuid():N}");
        var data = Encoding.UTF8.GetBytes("The quick brown fox");

        var signature = session.Sign(SignMechanism, data, privateKey);

        Assert.NotEmpty(signature);
        Assert.True(session.Verify(SignMechanism, data, signature, publicKey));
    }

    [Fact]
    public void Generates_ec_keypair_and_round_trips_an_ecdsa_signature()
    {
        if (!fixture.SupportsEcdsaSha256()) { return; } // SoftHSM 2.5.0 lacks CKM_ECDSA_SHA256

        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, privateKey) = session.GenerateEcKeyPair($"ec-{Guid.NewGuid():N}");
        var data = Encoding.UTF8.GetBytes("The quick brown fox");

        var signature = session.Sign(CK_MECHANISM_TYPE.CKM_ECDSA_SHA256, data, privateKey);

        Assert.NotEmpty(signature);
        Assert.True(session.Verify(CK_MECHANISM_TYPE.CKM_ECDSA_SHA256, data, signature, publicKey));
        Assert.False(session.Verify(CK_MECHANISM_TYPE.CKM_ECDSA_SHA256, Encoding.UTF8.GetBytes("tampered"), signature, publicKey));
    }

    [Fact]
    public void Verify_fails_for_tampered_data()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, privateKey) = session.GenerateRsaKeyPair($"tamper-{Guid.NewGuid():N}");
        var signature = session.Sign(SignMechanism, Encoding.UTF8.GetBytes("original"), privateKey);

        Assert.False(session.Verify(SignMechanism, Encoding.UTF8.GetBytes("tampered"), signature, publicKey));
    }

    [Fact]
    public void GetInfo_reports_softhsm_manufacturer()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());

        var info = library.GetInfo();

        Assert.Contains("SoftHSM", info.ManufacturerId.AsPkcs11String());
        Assert.True(info.CryptokiVersion.Major >= 2);
    }

    [Fact]
    public void GetSessionInfo_tracks_slot_and_login_state()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();

        var before = session.GetSessionInfo();
        Assert.Equal(session.Slot, before.SlotId);
        Assert.Equal(CK_STATE.CKS_RW_PUBLIC_SESSION, before.State);

        using var _ = session.Login(SoftHsmFixture.UserPin);
        Assert.Equal(CK_STATE.CKS_RW_USER_FUNCTIONS, session.GetSessionInfo().State);
    }

    [Fact]
    public void GetMechanismInfo_reports_rsa_keygen_capability()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();

        var info = library.GetMechanismInfo(session.Slot, CK_MECHANISM_TYPE.CKM_RSA_PKCS_KEY_PAIR_GEN);

        Assert.True(info.Flags.HasFlag(CK_MECHANISM_INFO_FLAGS.CKF_GENERATE_KEY_PAIR));
        Assert.True(info.MinKeySize <= 2048 && 2048 <= info.MaxKeySize);
    }

    [Fact]
    public void Reads_back_attributes_of_a_generated_rsa_keypair()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var label = $"attr-{Guid.NewGuid():N}";
        var (publicKey, privateKey) = session.GenerateRsaKeyPair(label);

        Assert.Equal(label, session.GetLabel(publicKey));
        Assert.Equal(label, session.GetLabel(privateKey));
        Assert.Equal(CK_OBJECT_CLASS.CKO_PUBLIC_KEY, session.GetObjectClass(publicKey));
        Assert.Equal(CK_OBJECT_CLASS.CKO_PRIVATE_KEY, session.GetObjectClass(privateKey));
        Assert.Equal(CK_KEY_TYPE.CKK_RSA, session.GetKeyType(publicKey));

        var modulus = session.GetAttributeValue(publicKey, CK_ATTRIBUTE_TYPE.CKA_MODULUS);
        Assert.Equal(256, modulus.Length); // 2048-bit default
    }

    [Fact]
    public void Reads_back_ec_point_of_a_generated_ec_keypair()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, _2) = session.GenerateEcKeyPair($"ecattr-{Guid.NewGuid():N}");

        var ecPoint = session.GetAttributeValue(publicKey, CK_ATTRIBUTE_TYPE.CKA_EC_POINT);

        // DER octet string wrapping an uncompressed P-256 point: 04 41 04 || X(32) || Y(32).
        Assert.Equal(67, ecPoint.Length);
        Assert.Equal(0x04, ecPoint[0]);
    }

    [Fact]
    public void Reading_a_sensitive_attribute_throws_pkcs11_exception()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var (_1, privateKey) = session.GenerateRsaKeyPair($"sens-{Guid.NewGuid():N}");

        var exception = Assert.Throws<Pkcs11Exception>(
            () => session.GetAttributeValue(privateKey, CK_ATTRIBUTE_TYPE.CKA_PRIVATE_EXPONENT));

        Assert.Equal(CK_RV.CKR_ATTRIBUTE_SENSITIVE, exception.ReturnValue);
    }

    [Fact]
    public void Login_with_wrong_pin_throws_pkcs11_exception()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();

        var exception = Assert.Throws<Pkcs11Exception>(() => session.Login("00000000"));

        Assert.Equal(CK_RV.CKR_PIN_INCORRECT, exception.ReturnValue);
    }
}
