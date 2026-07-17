using CertificateAuthority;
using Pkcs11Interop;
using Pkcs11Interop.DataStructures;

namespace Pkcs11Signing;

/// <summary>
/// <see cref="ICertificateSigner"/> backed by a PKCS#11 private key. The session
/// must be logged in; the signer does not own the session or the key.
/// </summary>
public sealed class Pkcs11CertificateSigner(
    Pkcs11Session session, NativeULong privateKeyHandle, SignatureAlgorithm signatureAlgorithm) : ICertificateSigner
{
    public SignatureAlgorithm SignatureAlgorithm => signatureAlgorithm;

    public byte[] Sign(byte[] data)
    {
        var rawSignature = session.Sign(MechanismFor(signatureAlgorithm), data, privateKeyHandle);

        return signatureAlgorithm.IsEcdsa()
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
