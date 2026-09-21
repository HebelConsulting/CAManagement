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

    /// <summary>The MGF1 variant OAEP pairs with a hash — RFC 8017 pairs them, and every mainstream
    /// implementation (including .NET's <c>RSAEncryptionPadding.OaepSHA256</c>) assumes the pairing, so
    /// offering them independently would only manufacture interop failures.</summary>
    public static CK_RSA_PKCS_MGF_TYPE Mgf1For(CK_MECHANISM_TYPE hashAlgorithm) => hashAlgorithm switch
    {
        CK_MECHANISM_TYPE.CKM_SHA_1 => CK_RSA_PKCS_MGF_TYPE.CKG_MGF1_SHA1,
        CK_MECHANISM_TYPE.CKM_SHA256 => CK_RSA_PKCS_MGF_TYPE.CKG_MGF1_SHA256,
        CK_MECHANISM_TYPE.CKM_SHA384 => CK_RSA_PKCS_MGF_TYPE.CKG_MGF1_SHA384,
        CK_MECHANISM_TYPE.CKM_SHA512 => CK_RSA_PKCS_MGF_TYPE.CKG_MGF1_SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(hashAlgorithm), hashAlgorithm, "Unsupported OAEP hash."),
    };
}
