// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

/// <summary>Plain CK_ULONG-valued constants from pkcs11t.h (2.40).</summary>
public static class Pkcs11Constants
{
    public const byte CK_TRUE = 1;
    public const byte CK_FALSE = 0;

    public const NativeULong CK_UNAVAILABLE_INFORMATION = NativeULong.MaxValue; // ~0 in CK_ULONG width
    public const NativeULong CK_EFFECTIVELY_INFINITE = 0;
    public const NativeULong CK_INVALID_HANDLE = 0;

    // CK_CERTIFICATE_CATEGORY (CKA_CERTIFICATE_CATEGORY values)
    public const NativeULong CK_CERTIFICATE_CATEGORY_UNSPECIFIED = 0;
    public const NativeULong CK_CERTIFICATE_CATEGORY_TOKEN_USER = 1;
    public const NativeULong CK_CERTIFICATE_CATEGORY_AUTHORITY = 2;
    public const NativeULong CK_CERTIFICATE_CATEGORY_OTHER_ENTITY = 3;

    // CK_SECURITY_DOMAIN (CKA_JAVA_MIDP_SECURITY_DOMAIN values)
    public const NativeULong CK_SECURITY_DOMAIN_UNSPECIFIED = 0;
    public const NativeULong CK_SECURITY_DOMAIN_MANUFACTURER = 1;
    public const NativeULong CK_SECURITY_DOMAIN_OPERATOR = 2;
    public const NativeULong CK_SECURITY_DOMAIN_THIRD_PARTY = 3;

    // CK_OTP_FORMAT (CKA_OTP_FORMAT values)
    public const NativeULong CK_OTP_FORMAT_DECIMAL = 0;
    public const NativeULong CK_OTP_FORMAT_HEXADECIMAL = 1;
    public const NativeULong CK_OTP_FORMAT_ALPHANUMERIC = 2;
    public const NativeULong CK_OTP_FORMAT_BINARY = 3;

    // CK_OTP_PARAM requirement modes (CKA_OTP_*_REQUIREMENT values)
    public const NativeULong CK_OTP_PARAM_IGNORED = 0;
    public const NativeULong CK_OTP_PARAM_OPTIONAL = 1;
    public const NativeULong CK_OTP_PARAM_MANDATORY = 2;

    // C_WaitForSlotEvent flag
    public const NativeULong CKF_DONT_BLOCK = 1;
}
