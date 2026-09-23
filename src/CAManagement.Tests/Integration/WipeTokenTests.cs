using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Extensions;

namespace CAManagement.Tests.Integration;

/// <summary>
/// What <c>wipe-token</c> promises, against a real token: the objects are destroyed, the label is
/// replaced, and the SLOT remains — PKCS#11 has no operation that removes one, which is why the verb
/// is not called delete-token.
/// </summary>
[Collection(SoftHsmCollection.Name)]
public sealed class WipeTokenTests(SoftHsmFixture fixture)
{
    [Fact]
    public void Wiping_a_token_destroys_its_objects_and_relabels_it_while_the_slot_remains()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());

        // Its OWN token, never the fixture's shared one: a test that mutates creates what it mutates.
        var wipeLabel = $"wipe-{Guid.NewGuid():N}"[..20];
        var retiredLabel = $"retired-{Guid.NewGuid():N}"[..20];

        library.InitializeToken(library.FindFreeSlot(), SoftHsmFixture.SoPin, wipeLabel);

        // SoftHSM REASSIGNS the slot id when it initializes a free slot, so re-resolve by label
        // rather than trusting the id we passed in.
        var slot = SlotLabelled(library, wipeLabel);
        SetUserPin(library, slot);

        var keyLabel = $"probe-{Guid.NewGuid():N}";
        using (var session = library.OpenSession(slot, readWrite: true))
        using (session.Login(SoftHsmFixture.UserPin))
        {
            session.GenerateRsaKeyPair(keyLabel);
            Assert.NotEmpty(session.FindObjects(CK_OBJECT_CLASS.CKO_PRIVATE_KEY, keyLabel));
        }

        var tokensBefore = library.GetSlotList(tokenPresent: true).Length;

        library.CloseAllSessions(slot);
        library.InitializeToken(slot, SoftHsmFixture.SoPin, retiredLabel);

        var wiped = SlotLabelled(library, retiredLabel);
        var info = library.GetTokenInfo(wiped);

        Assert.True(info.Flags.HasFlag(CK_TOKEN_INFO_FLAGS.CKF_TOKEN_INITIALIZED));
        Assert.Equal(tokensBefore, library.GetSlotList(tokenPresent: true).Length); // no slot was removed
        Assert.DoesNotContain(library.GetSlotList(tokenPresent: true),
            s => library.GetTokenInfo(s).Label.AsPkcs11String().Trim() == wipeLabel); // the old label is gone

        SetUserPin(library, wiped);
        using (var session = library.OpenSession(wiped, readWrite: true))
        using (session.Login(SoftHsmFixture.UserPin))
        {
            Assert.Empty(session.FindObjects(CK_OBJECT_CLASS.CKO_PRIVATE_KEY, keyLabel)); // the keys are gone
        }
    }

    private static NativeULong SlotLabelled(Pkcs11Library library, string label) =>
        library.GetSlotList(tokenPresent: true)
            .Single(slot => library.GetTokenInfo(slot).Label.AsPkcs11String().Trim() == label);

    private static void SetUserPin(Pkcs11Library library, NativeULong slot)
    {
        using var session = library.OpenSession(slot, readWrite: true);
        using var login = session.Login(SoftHsmFixture.SoPin, CKU.CKU_SO);
        session.InitializeUserPin(SoftHsmFixture.UserPin);
    }
}
