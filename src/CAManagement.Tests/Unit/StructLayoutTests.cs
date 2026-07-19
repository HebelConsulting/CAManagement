using System.Runtime.InteropServices;
using CAManagement.Pkcs11.DataStructures;

namespace CAManagement.Tests.Unit;

/// <summary>
/// Locks the marshalled size of every PKCS#11 struct to its platform ABI:
/// Unix LP64 (natural alignment, 8-byte CK_ULONG) or Windows LLP64
/// (#pragma pack(1), 4-byte CK_ULONG). A failure here means the native ABI
/// contract changed — sizes must match the C structs from pkcs11t.h (2.40).
/// </summary>
public sealed class StructLayoutTests
{
    [Theory]
#if WINDOWS
    [InlineData(typeof(CK_VERSION), 2)]
    [InlineData(typeof(CK_ATTRIBUTE), 16)]
    [InlineData(typeof(CK_MECHANISM), 16)]
    [InlineData(typeof(CK_C_INITIALIZE_ARGS), 44)]
    [InlineData(typeof(CK_SLOT_INFO), 104)]
    [InlineData(typeof(CK_TOKEN_INFO), 160)]
    [InlineData(typeof(CK_INFO), 72)]
    [InlineData(typeof(CK_SESSION_INFO), 16)]
    [InlineData(typeof(CK_MECHANISM_INFO), 12)]
    [InlineData(typeof(CK_DATE), 8)]
    [InlineData(typeof(CK_RSA_PKCS_PSS_PARAMS), 12)]
    [InlineData(typeof(CK_RSA_PKCS_OAEP_PARAMS), 24)]
    [InlineData(typeof(CK_ECDH1_DERIVE_PARAMS), 28)]
#else
    [InlineData(typeof(CK_VERSION), 2)]
    [InlineData(typeof(CK_ATTRIBUTE), 24)]
    [InlineData(typeof(CK_MECHANISM), 24)]
    [InlineData(typeof(CK_C_INITIALIZE_ARGS), 48)]
    [InlineData(typeof(CK_SLOT_INFO), 112)]
    [InlineData(typeof(CK_TOKEN_INFO), 208)]
    [InlineData(typeof(CK_INFO), 88)]
    [InlineData(typeof(CK_SESSION_INFO), 32)]
    [InlineData(typeof(CK_MECHANISM_INFO), 24)]
    [InlineData(typeof(CK_DATE), 8)]
    [InlineData(typeof(CK_RSA_PKCS_PSS_PARAMS), 24)]
    [InlineData(typeof(CK_RSA_PKCS_OAEP_PARAMS), 40)]
    [InlineData(typeof(CK_ECDH1_DERIVE_PARAMS), 40)]
#endif
    public void Struct_has_expected_lp64_size(Type structType, int expectedSize)
    {
        Assert.Equal(expectedSize, Marshal.SizeOf(structType));
    }

    [Fact]
    public void Constants_match_pkcs11t_h()
    {
        Assert.Equal(NativeULong.MaxValue, Pkcs11Constants.CK_UNAVAILABLE_INFORMATION);
        Assert.Equal((NativeULong)0, Pkcs11Constants.CK_INVALID_HANDLE);
        Assert.Equal(3UL, (ulong)CK_STATE.CKS_RW_USER_FUNCTIONS);
        Assert.Equal(0UL, (ulong)CK_CERTIFICATE_TYPE.CKC_X_509);
        Assert.Equal(2UL, (ulong)CK_RSA_PKCS_MGF_TYPE.CKG_MGF1_SHA256);
        Assert.Equal(6UL, (ulong)CK_EC_KDF_TYPE.CKD_SHA256_KDF);
        Assert.Equal(0x10000UL, (ulong)CK_MECHANISM_INFO_FLAGS.CKF_GENERATE_KEY_PAIR);
    }
}
