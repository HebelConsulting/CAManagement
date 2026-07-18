// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

[Flags]
public enum CK_OTP_FLAGS : NativeULong
{
    CKF_NEXT_OTP = 0x00000001,
    CKF_EXCLUDE_TIME = 0x00000002,
    CKF_EXCLUDE_COUNTER = 0x00000004,
    CKF_EXCLUDE_CHALLENGE = 0x00000008,
    CKF_EXCLUDE_PIN = 0x00000010,
    CKF_USER_FRIENDLY_OTP = 0x00000020,
}
