using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;

namespace CAManagement.Tests.Unit;

public sealed class MechanismsTests
{
    [Theory]
    [InlineData(CK_MECHANISM_TYPE.CKM_RSA_PKCS, CK_KEY_TYPE.CKK_RSA)]
    [InlineData(CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS, CK_KEY_TYPE.CKK_RSA)]
    [InlineData(CK_MECHANISM_TYPE.CKM_ECDSA, CK_KEY_TYPE.CKK_ECDSA)]
    [InlineData(CK_MECHANISM_TYPE.CKM_ECDSA_SHA256, CK_KEY_TYPE.CKK_ECDSA)]
    public void Maps_signing_mechanism_to_key_type(CK_MECHANISM_TYPE mechanism, CK_KEY_TYPE expected)
    {
        Assert.Equal(expected, Mechanisms.KeyTypeFor(mechanism));
    }

    [Fact]
    public void Throws_for_unsupported_mechanism()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Mechanisms.KeyTypeFor(CK_MECHANISM_TYPE.CKM_AES_GCM));
    }

    [Theory]
    [InlineData(CK_MECHANISM_TYPE.CKM_SHA_1, CK_RSA_PKCS_MGF_TYPE.CKG_MGF1_SHA1)]
    [InlineData(CK_MECHANISM_TYPE.CKM_SHA256, CK_RSA_PKCS_MGF_TYPE.CKG_MGF1_SHA256)]
    [InlineData(CK_MECHANISM_TYPE.CKM_SHA384, CK_RSA_PKCS_MGF_TYPE.CKG_MGF1_SHA384)]
    [InlineData(CK_MECHANISM_TYPE.CKM_SHA512, CK_RSA_PKCS_MGF_TYPE.CKG_MGF1_SHA512)]
    public void Mgf1_pairs_with_its_hash(CK_MECHANISM_TYPE hash, CK_RSA_PKCS_MGF_TYPE expected) =>
        Assert.Equal(expected, Mechanisms.Mgf1For(hash));

    [Fact]
    public void Mgf1_for_a_non_hash_mechanism_throws() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Mechanisms.Mgf1For(CK_MECHANISM_TYPE.CKM_RSA_PKCS));
}
