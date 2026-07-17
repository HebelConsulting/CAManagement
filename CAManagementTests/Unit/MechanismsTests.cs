using Pkcs11Interop;
using Pkcs11Interop.DataStructures;

namespace CAManagementTests.Unit;

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
}
