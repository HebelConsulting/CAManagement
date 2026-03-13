using NativeULong = System.UInt64;

// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

public enum CK_MECHANISM_TYPE : NativeULong
{
    CKM_RSA_PKCS = 0x00000001UL,
    CKM_SHA256_RSA_PKCS = 0x00000040UL,
    CKM_ECDSA = 0x00001041UL,
    CKM_ECDSA_SHA256 = 0x00001044UL,
}