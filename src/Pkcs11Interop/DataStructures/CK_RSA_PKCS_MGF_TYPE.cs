// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

public enum CK_RSA_PKCS_MGF_TYPE : NativeULong
{
    CKG_MGF1_SHA1 = 0x00000001UL,
    CKG_MGF1_SHA256 = 0x00000002UL,
    CKG_MGF1_SHA384 = 0x00000003UL,
    CKG_MGF1_SHA512 = 0x00000004UL,
    CKG_MGF1_SHA224 = 0x00000005UL,
}
