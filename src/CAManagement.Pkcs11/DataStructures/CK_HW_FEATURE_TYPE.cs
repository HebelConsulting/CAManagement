// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

public enum CK_HW_FEATURE_TYPE : NativeULong
{
    CKH_MONOTONIC_COUNTER = 0x00000001,
    CKH_CLOCK = 0x00000002,
    CKH_USER_INTERFACE = 0x00000003,
    CKH_VENDOR_DEFINED = 0x80000000,
}
