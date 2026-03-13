using NativeULong = System.UInt64;

// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

[Flags]
public enum CK_RV : NativeULong
{
    CKR_OK = 0x00000000UL,
}