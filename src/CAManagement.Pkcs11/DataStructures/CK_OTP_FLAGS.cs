// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

[Flags]
public enum CK_OTP_FLAGS : NativeULong
{
    CKF_NEXT_OTP = 0x00000001UL,
    CKF_EXCLUDE_TIME = 0x00000002UL,
    CKF_EXCLUDE_COUNTER = 0x00000004UL,
    CKF_EXCLUDE_CHALLENGE = 0x00000008UL,
    CKF_EXCLUDE_PIN = 0x00000010UL,
    CKF_USER_FRIENDLY_OTP = 0x00000020UL,
}
