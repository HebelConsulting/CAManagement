using System.Security.Cryptography;

namespace CertificateAuthority;

public static class SignatureAlgorithmExtensions
{
    public static bool IsEcdsa(this SignatureAlgorithm algorithm) => algorithm is
        SignatureAlgorithm.EcdsaWithSha256 or SignatureAlgorithm.EcdsaWithSha384 or SignatureAlgorithm.EcdsaWithSha512;

    public static HashAlgorithmName HashAlgorithmName(this SignatureAlgorithm algorithm) => algorithm switch
    {
        SignatureAlgorithm.Sha256WithRsa or SignatureAlgorithm.EcdsaWithSha256 => System.Security.Cryptography.HashAlgorithmName.SHA256,
        SignatureAlgorithm.Sha384WithRsa or SignatureAlgorithm.EcdsaWithSha384 => System.Security.Cryptography.HashAlgorithmName.SHA384,
        SignatureAlgorithm.Sha512WithRsa or SignatureAlgorithm.EcdsaWithSha512 => System.Security.Cryptography.HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported signature algorithm."),
    };

    public static SignatureAlgorithm FromOid(string oid) => oid switch
    {
        Oids.Sha256WithRsaEncryption => SignatureAlgorithm.Sha256WithRsa,
        Oids.Sha384WithRsaEncryption => SignatureAlgorithm.Sha384WithRsa,
        Oids.Sha512WithRsaEncryption => SignatureAlgorithm.Sha512WithRsa,
        Oids.EcdsaWithSha256 => SignatureAlgorithm.EcdsaWithSha256,
        Oids.EcdsaWithSha384 => SignatureAlgorithm.EcdsaWithSha384,
        Oids.EcdsaWithSha512 => SignatureAlgorithm.EcdsaWithSha512,
        _ => throw new NotSupportedException($"Unsupported signature algorithm OID {oid}."),
    };
}
