// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

public enum CK_HW_FEATURE_TYPE : NativeULong
{
    CKH_MONOTONIC_COUNTER = 0x00000001UL,
    CKH_CLOCK = 0x00000002UL,
    CKH_USER_INTERFACE = 0x00000003UL,
    CKH_VENDOR_DEFINED = 0x80000000UL,
}
