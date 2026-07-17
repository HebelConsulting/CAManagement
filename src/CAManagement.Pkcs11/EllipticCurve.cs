namespace CAManagement.Pkcs11;

/// <summary>Named elliptic curves supported for key generation.</summary>
public enum EllipticCurve
{
    NistP256,
    NistP384,
    NistP521,
}

public static class EllipticCurveExtensions
{
    /// <summary>
    /// The DER-encoded named-curve OID used as the <c>CKA_EC_PARAMS</c> attribute.
    /// Precomputed here so the PKCS#11 library stays free of ASN.1 concerns (those
    /// belong to the separate CA/DER library).
    /// </summary>
    public static byte[] EcParams(this EllipticCurve curve) => curve switch
    {
        // 1.2.840.10045.3.1.7 (secp256r1 / prime256v1)
        EllipticCurve.NistP256 => [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        // 1.3.132.0.34 (secp384r1)
        EllipticCurve.NistP384 => [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
        // 1.3.132.0.35 (secp521r1)
        EllipticCurve.NistP521 => [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23],
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unsupported curve."),
    };
}
