// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

public enum CK_RSA_PKCS_MGF_TYPE : NativeULong
{
    CKG_MGF1_SHA1 = 0x00000001,
    CKG_MGF1_SHA256 = 0x00000002,
    CKG_MGF1_SHA384 = 0x00000003,
    CKG_MGF1_SHA512 = 0x00000004,
    CKG_MGF1_SHA224 = 0x00000005,
}
