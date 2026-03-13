// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

public enum CK_KEY_TYPE : uint
{
    CKK_RSA = 0x00000000,
    CKK_DSA = 0x00000001,
    CKK_DH =  0x00000002,
    CKK_ECDSA =  0x00000003,
    CKK_EC =  0x00000003,
}