using CAManagement.Pkcs11.DataStructures;

namespace CAManagement.Pkcs11;

/// <summary>Helpers relating signing mechanisms to key types.</summary>
public static class Mechanisms
{
    public static CK_KEY_TYPE KeyTypeFor(CK_MECHANISM_TYPE mechanismType) => mechanismType switch
    {
        CK_MECHANISM_TYPE.CKM_RSA_PKCS => CK_KEY_TYPE.CKK_RSA,
        CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS => CK_KEY_TYPE.CKK_RSA,
        CK_MECHANISM_TYPE.CKM_SHA384_RSA_PKCS => CK_KEY_TYPE.CKK_RSA,
        CK_MECHANISM_TYPE.CKM_SHA512_RSA_PKCS => CK_KEY_TYPE.CKK_RSA,
        CK_MECHANISM_TYPE.CKM_ECDSA => CK_KEY_TYPE.CKK_ECDSA,
        CK_MECHANISM_TYPE.CKM_ECDSA_SHA256 => CK_KEY_TYPE.CKK_ECDSA,
        _ => throw new ArgumentOutOfRangeException(nameof(mechanismType), mechanismType, "Unsupported signing mechanism."),
    };
}
