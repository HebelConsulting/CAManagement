using NativeULong = System.UInt64;

// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

public enum CK_OBJECT_CLASS : NativeULong
{
    CKO_PUBLIC_KEY  = 0x00000002UL,
    CKO_PRIVATE_KEY = 0x00000003UL,
}