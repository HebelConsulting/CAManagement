using CAManagement.X509;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;

namespace CAManagement.Pkcs11.Signing;

/// <summary>
/// <see cref="ICertificateSigner"/> backed by a PKCS#11 private key. The session
/// must be logged in; the signer does not own the session or the key.
/// </summary>
public sealed class Pkcs11CertificateSigner : ICertificateSigner
{
    private readonly Pkcs11Session _session;
    private readonly NativeULong _privateKeyHandle;

    public Pkcs11CertificateSigner(Pkcs11Session session, NativeULong privateKeyHandle, SignatureAlgorithm signatureAlgorithm)
    {
        // Fail here, not inside C_Sign: SoftHSM dispatches by the requested mechanism rather than the
        // key object's type and SEGFAULTS on a mismatch (RSA_size(NULL) under OSSLRSA::signFinal —
        // issue #9), so this guard is the only readable error a caller ever gets. A real HSM would
        // return CKR_KEY_TYPE_INCONSISTENT, but by then the message names neither the key nor the fix.
        var required = signatureAlgorithm.IsEcdsa() ? CK_KEY_TYPE.CKK_ECDSA : CK_KEY_TYPE.CKK_RSA;
        var actual = session.GetKeyType(privateKeyHandle);
        if (actual != required)
        {
            throw new ArgumentException(
                $"{signatureAlgorithm} needs a {required} private key, but the key on the token is {actual}. " +
                $"Pass a matching algorithm, or use {nameof(Pkcs11CertificateSigner)}.{nameof(ForKey)} to derive it from the key.",
                nameof(signatureAlgorithm));
        }

        _session = session;
        _privateKeyHandle = privateKeyHandle;
        SignatureAlgorithm = signatureAlgorithm;
    }

    public SignatureAlgorithm SignatureAlgorithm { get; }

    /// <summary>
    /// Builds a signer whose algorithm is derived from the key's own <c>CKA_KEY_TYPE</c>
    /// (RSA → SHA-256/RSA, EC → SHA-256/ECDSA) — the "sign with this key" shape that cannot
    /// mismatch. Callers that need a different hash width keep the explicit constructor.
    /// </summary>
    public static Pkcs11CertificateSigner ForKey(Pkcs11Session session, NativeULong privateKeyHandle) =>
        new(session, privateKeyHandle, session.GetKeyType(privateKeyHandle) switch
        {
            CK_KEY_TYPE.CKK_RSA => SignatureAlgorithm.Sha256WithRsa,
            CK_KEY_TYPE.CKK_ECDSA => SignatureAlgorithm.EcdsaWithSha256,
            var keyType => throw new NotSupportedException($"No signature algorithm for key type {keyType}."),
        });

    public byte[] Sign(byte[] data)
    {
        var rawSignature = _session.Sign(MechanismFor(SignatureAlgorithm), data, _privateKeyHandle);

        return SignatureAlgorithm.IsEcdsa()
            ? EcdsaSignatureConverter.RawToDer(rawSignature)
            : rawSignature;
    }

    private static CK_MECHANISM_TYPE MechanismFor(SignatureAlgorithm algorithm) => algorithm switch
    {
        SignatureAlgorithm.Sha256WithRsa => CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS,
        SignatureAlgorithm.Sha384WithRsa => CK_MECHANISM_TYPE.CKM_SHA384_RSA_PKCS,
        SignatureAlgorithm.Sha512WithRsa => CK_MECHANISM_TYPE.CKM_SHA512_RSA_PKCS,
        SignatureAlgorithm.EcdsaWithSha256 => CK_MECHANISM_TYPE.CKM_ECDSA_SHA256,
        SignatureAlgorithm.EcdsaWithSha384 => CK_MECHANISM_TYPE.CKM_ECDSA_SHA384,
        SignatureAlgorithm.EcdsaWithSha512 => CK_MECHANISM_TYPE.CKM_ECDSA_SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported signature algorithm."),
    };
}
