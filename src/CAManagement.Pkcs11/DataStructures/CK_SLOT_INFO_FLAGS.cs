// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

[Flags]
public enum CK_SLOT_INFO_FLAGS : NativeULong
{
    CKF_TOKEN_PRESENT    = 0x00000001,
    CKF_REMOVABLE_DEVICE = 0x00000002,
    CKF_HW_SLOT          = 0x00000004,
}