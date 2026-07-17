namespace CAManagement.X509;

/// <summary>Signature algorithms supported for certificate signing (v1 scope).</summary>
public enum SignatureAlgorithm
{
    Sha256WithRsa,
    Sha384WithRsa,
    Sha512WithRsa,
    EcdsaWithSha256,
    EcdsaWithSha384,
    EcdsaWithSha512,
}
