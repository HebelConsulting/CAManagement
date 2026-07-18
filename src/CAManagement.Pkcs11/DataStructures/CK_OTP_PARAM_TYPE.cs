// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

public enum CK_OTP_PARAM_TYPE : NativeULong
{
    CK_OTP_VALUE = 0,
    CK_OTP_PIN = 1,
    CK_OTP_CHALLENGE = 2,
    CK_OTP_TIME = 3,
    CK_OTP_COUNTER = 4,
    CK_OTP_FLAGS = 5,
    CK_OTP_OUTPUT_LENGTH = 6,
    CK_OTP_OUTPUT_FORMAT = 7,
}
