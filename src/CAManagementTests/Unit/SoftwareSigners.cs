using System.Security.Cryptography;
using CertificateAuthority;

namespace CAManagementTests.Unit;

/// <summary>Software-key signers so the DER library tests run without an HSM (SPEC D6).</summary>
internal sealed class EcdsaSoftwareSigner(ECDsa key) : ICertificateSigner
{
    public SignatureAlgorithm SignatureAlgorithm => SignatureAlgorithm.EcdsaWithSha256;

    public byte[] Sign(byte[] data) =>
        key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
}

internal sealed class RsaSoftwareSigner(RSA key) : ICertificateSigner
{
    public SignatureAlgorithm SignatureAlgorithm => SignatureAlgorithm.Sha256WithRsa;

    public byte[] Sign(byte[] data) =>
        key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
}
