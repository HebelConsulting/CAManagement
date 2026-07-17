// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

public enum CK_OTP_PARAM_TYPE : NativeULong
{
    CK_OTP_VALUE = 0UL,
    CK_OTP_PIN = 1UL,
    CK_OTP_CHALLENGE = 2UL,
    CK_OTP_TIME = 3UL,
    CK_OTP_COUNTER = 4UL,
    CK_OTP_FLAGS = 5UL,
    CK_OTP_OUTPUT_LENGTH = 6UL,
    CK_OTP_OUTPUT_FORMAT = 7UL,
}
