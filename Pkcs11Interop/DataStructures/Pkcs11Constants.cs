// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

/// <summary>Plain CK_ULONG-valued constants from pkcs11t.h (2.40).</summary>
public static class Pkcs11Constants
{
    public const byte CK_TRUE = 1;
    public const byte CK_FALSE = 0;

    public const NativeULong CK_UNAVAILABLE_INFORMATION = ~0UL;
    public const NativeULong CK_EFFECTIVELY_INFINITE = 0UL;
    public const NativeULong CK_INVALID_HANDLE = 0UL;

    // CK_CERTIFICATE_CATEGORY (CKA_CERTIFICATE_CATEGORY values)
    public const NativeULong CK_CERTIFICATE_CATEGORY_UNSPECIFIED = 0UL;
    public const NativeULong CK_CERTIFICATE_CATEGORY_TOKEN_USER = 1UL;
    public const NativeULong CK_CERTIFICATE_CATEGORY_AUTHORITY = 2UL;
    public const NativeULong CK_CERTIFICATE_CATEGORY_OTHER_ENTITY = 3UL;

    // CK_SECURITY_DOMAIN (CKA_JAVA_MIDP_SECURITY_DOMAIN values)
    public const NativeULong CK_SECURITY_DOMAIN_UNSPECIFIED = 0UL;
    public const NativeULong CK_SECURITY_DOMAIN_MANUFACTURER = 1UL;
    public const NativeULong CK_SECURITY_DOMAIN_OPERATOR = 2UL;
    public const NativeULong CK_SECURITY_DOMAIN_THIRD_PARTY = 3UL;

    // CK_OTP_FORMAT (CKA_OTP_FORMAT values)
    public const NativeULong CK_OTP_FORMAT_DECIMAL = 0UL;
    public const NativeULong CK_OTP_FORMAT_HEXADECIMAL = 1UL;
    public const NativeULong CK_OTP_FORMAT_ALPHANUMERIC = 2UL;
    public const NativeULong CK_OTP_FORMAT_BINARY = 3UL;

    // CK_OTP_PARAM requirement modes (CKA_OTP_*_REQUIREMENT values)
    public const NativeULong CK_OTP_PARAM_IGNORED = 0UL;
    public const NativeULong CK_OTP_PARAM_OPTIONAL = 1UL;
    public const NativeULong CK_OTP_PARAM_MANDATORY = 2UL;

    // C_WaitForSlotEvent flag
    public const NativeULong CKF_DONT_BLOCK = 1UL;
}
