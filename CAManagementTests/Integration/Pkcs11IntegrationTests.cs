using System.Text;
using Pkcs11Interop;
using Pkcs11Interop.DataStructures;

namespace CAManagementTests.Integration;

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

        Assert.NotEqual(0UL, session.Handle);
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
    public void Login_with_wrong_pin_throws_pkcs11_exception()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();

        var exception = Assert.Throws<Pkcs11Exception>(() => session.Login("00000000"));

        Assert.Equal(CK_RV.CKR_PIN_INCORRECT, exception.ReturnValue);
    }
}
