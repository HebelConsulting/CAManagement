using System.Security.Cryptography;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Signing;

namespace CAManagement.Tests.Integration;

// KEK generations for envelope encryption (issue #1, the hybrid decision): generations are IDENTIFIED by
// versioned label — routing works with today's exact-label lookup — while CKA_ID is WRITTEN on both halves
// of every pair so a future ID-addressed consumer (smart cards) finds the ids already present instead of
// needing a token backfill. Written, not yet searched: same posture as certificate import.
[Collection(SoftHsmCollection.Name)]
public sealed class KeyGenerationsTests(SoftHsmFixture fixture)
{
    [Fact]
    public void Both_halves_of_a_pair_carry_the_supplied_id()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var id = RandomNumberGenerator.GetBytes(16);
        var (publicKey, privateKey) = session.GenerateRsaKeyPair(
            $"gen-{Guid.NewGuid():N}", id: id, usage: Pkcs11KeyPairUsage.Encryption);

        // The convention CKA_ID exists for: one pair, one id — a reader holding either half finds the same.
        Assert.Equal(id, session.GetAttributeValue(publicKey, CK_ATTRIBUTE_TYPE.CKA_ID));
        Assert.Equal(id, session.GetAttributeValue(privateKey, CK_ATTRIBUTE_TYPE.CKA_ID));
    }

    [Fact]
    public void A_pair_without_an_id_still_generates()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, _) = session.GenerateRsaKeyPair($"noid-{Guid.NewGuid():N}");

        Assert.NotEqual((NativeULong)0, publicKey);
    }

    // The consumer's whole rotation story in one test: two generations coexist under versioned labels, a
    // data key wrapped in software against generation 1's public half is unwrapped by routing on generation
    // 1's LABEL — while generation 2 (the "current" one new wraps would use) resolves independently. This is
    // what "rolling keys" means mechanically, and it needs no lookup machinery beyond exact-label find.
    [Fact]
    public void Two_generations_coexist_and_unwrap_routes_by_label()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var stem = $"kek-{Guid.NewGuid():N}";
        session.GenerateRsaKeyPair($"{stem}-v1",
            id: RandomNumberGenerator.GetBytes(16), usage: Pkcs11KeyPairUsage.Encryption);
        session.GenerateRsaKeyPair($"{stem}-v2",
            id: RandomNumberGenerator.GetBytes(16), usage: Pkcs11KeyPairUsage.Encryption);

        // Route to generation 1 by label alone, as the wrapped-DEK record will.
        var v1Public = Assert.Single(session.FindObjects(CK_OBJECT_CLASS.CKO_PUBLIC_KEY, $"{stem}-v1"));
        var v1Private = Assert.Single(session.FindObjects(CK_OBJECT_CLASS.CKO_PRIVATE_KEY, $"{stem}-v1"));
        Assert.Single(session.FindObjects(CK_OBJECT_CLASS.CKO_PRIVATE_KEY, $"{stem}-v2"));

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Pkcs11PublicKeyReader.Read(session, v1Public).Encode(), out _);
        var dataKey = RandomNumberGenerator.GetBytes(32);
        var wrapped = rsa.Encrypt(dataKey, RSAEncryptionPadding.OaepSHA1);

        Assert.Equal(dataKey, session.DecryptRsaOaep(wrapped, v1Private, CK_MECHANISM_TYPE.CKM_SHA_1));
    }

    // SoftHSM does NOT enforce usage flags — an Encryption-usage key also signs here, so this suite cannot
    // prove the flag separation; only a strict HSM can refuse the wrong usage. What CAN be pinned is that
    // the flags are WRITTEN as requested, which is the half a strict HSM will later read.
    [Fact]
    public void Usage_flags_are_written_as_requested()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (_, encPrivate) = session.GenerateRsaKeyPair(
            $"usage-e-{Guid.NewGuid():N}", usage: Pkcs11KeyPairUsage.Encryption);
        var (_, sigPrivate) = session.GenerateRsaKeyPair($"usage-s-{Guid.NewGuid():N}");

        Assert.Equal([1], session.GetAttributeValue(encPrivate, CK_ATTRIBUTE_TYPE.CKA_DECRYPT));
        Assert.Equal([1], session.GetAttributeValue(sigPrivate, CK_ATTRIBUTE_TYPE.CKA_SIGN));
    }
}
