// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

[Flags]
public enum CK_SLOT_INFO_FLAGS : NativeULong
{
    CKF_TOKEN_PRESENT    = 0x00000001UL,
    CKF_REMOVABLE_DEVICE = 0x00000002UL,
    CKF_HW_SLOT          = 0x00000004UL,
}