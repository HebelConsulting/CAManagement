using System.Text;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Extensions;

namespace CAManagement.Tests.Integration;

[Collection(SoftHsmCollection.Name)]
public sealed class TokenAndSlotTests(SoftHsmFixture fixture)
{
    // --- slot / mechanism introspection --------------------------------------

    [Fact] // closes the C_GetSlotInfo test gap
    public void GetSlotInfo_reports_a_present_softhsm_slot()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();

        var info = library.GetSlotInfo(session.Slot);

        Assert.Contains("SoftHSM", info.ManufacturerId.AsPkcs11String());
        Assert.True(info.Flags.HasFlag(CK_SLOT_INFO_FLAGS.CKF_TOKEN_PRESENT));
    }

    [Fact]
    public void GetMechanismList_includes_rsa_keygen_and_signing()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();

        var mechanisms = library.GetMechanismList(session.Slot);

        Assert.Contains(CK_MECHANISM_TYPE.CKM_RSA_PKCS_KEY_PAIR_GEN, mechanisms);
        Assert.Contains(CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS, mechanisms);
    }

    [Fact] // closes the C_CloseAllSessions test gap
    public void CloseAllSessions_invalidates_open_session_handles()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        var session = library.OpenSession(); // deliberately not disposed — it's about to be closed underneath us
        Assert.Equal(session.Slot, session.GetSessionInfo().SlotId);

        library.CloseAllSessions(session.Slot);

        var exception = Assert.Throws<Pkcs11Exception>(() => session.GetSessionInfo());
        Assert.True(exception.ReturnValue is CK_RV.CKR_SESSION_HANDLE_INVALID or CK_RV.CKR_SESSION_CLOSED);
    }

    // --- multi-part sign / verify --------------------------------------------

    [Fact]
    public void Multi_part_rsa_sign_verify_round_trips_and_matches_single_shot()
    {
        const CK_MECHANISM_TYPE mechanism = CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS;

        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, privateKey) = session.GenerateRsaKeyPair($"mp-{Guid.NewGuid():N}");
        byte[][] parts = ["The quick "u8.ToArray(), "brown fox "u8.ToArray(), "jumps over the lazy dog."u8.ToArray()];

        var signature = session.SignParts(mechanism, parts, privateKey);

        Assert.NotEmpty(signature);
        Assert.True(session.VerifyParts(mechanism, parts, signature, publicKey));

        // RSA PKCS#1 v1.5 is deterministic: multi-part over the parts must equal
        // single-shot over their concatenation.
        var whole = parts.SelectMany(p => p).ToArray();
        Assert.Equal(session.Sign(mechanism, whole, privateKey), signature);

        // A different part stream does not verify against the signature.
        Assert.False(session.VerifyParts(mechanism, ["tampered"u8.ToArray()], signature, publicKey));
    }

    // --- token / PIN administration ------------------------------------------

    [Fact]
    public void Init_token_set_user_pin_then_change_it()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());

        var slot = library.FindFreeSlot();
        Assert.False(library.GetTokenInfo(slot).Flags.HasFlag(CK_TOKEN_INFO_FLAGS.CKF_TOKEN_INITIALIZED));

        var label = $"admin-{Guid.NewGuid():N}"[..20];
        const string soPin = "87654321";
        const string userPin = "5678";
        const string newPin = "9999";

        // C_InitToken.
        library.InitializeToken(slot, soPin, label);
        var tokenInfo = library.GetTokenInfo(slot);
        Assert.Equal(label, tokenInfo.Label.AsPkcs11String());
        Assert.True(tokenInfo.Flags.HasFlag(CK_TOKEN_INFO_FLAGS.CKF_TOKEN_INITIALIZED));

        // C_InitPIN from an SO session.
        using (var soSession = library.OpenSession(slot, readWrite: true))
        using (soSession.Login(soPin, CKU.CKU_SO))
        {
            soSession.InitializeUserPin(userPin);
        }

        // The user PIN works; then C_SetPIN changes it.
        using (var userSession = library.OpenSession(slot, readWrite: true))
        using (userSession.Login(userPin))
        {
            userSession.SetPin(userPin, newPin);
        }

        // The new PIN logs in; the old one is rejected.
        using (var check = library.OpenSession(slot, readWrite: true))
        {
            using (check.Login(newPin)) { }
        }

        using (var check = library.OpenSession(slot, readWrite: true))
        {
            var exception = Assert.Throws<Pkcs11Exception>(() => check.Login(userPin));
            Assert.Equal(CK_RV.CKR_PIN_INCORRECT, exception.ReturnValue);
        }
    }
}
