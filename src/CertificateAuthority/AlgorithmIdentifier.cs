using System.Formats.Asn1;

namespace CertificateAuthority;

/// <summary>
/// RFC 5280 AlgorithmIdentifier: <c>SEQUENCE { algorithm OID, parameters ANY OPTIONAL }</c>.
/// RSA PKCS#1 v1.5 algorithms carry an explicit NULL parameter; ECDSA algorithms
/// omit the parameter entirely (RFC 5758 §3.2).
/// </summary>
public sealed record AlgorithmIdentifier(string Oid, bool HasNullParameters)
{
    public static AlgorithmIdentifier For(SignatureAlgorithm algorithm) => algorithm switch
    {
        SignatureAlgorithm.Sha256WithRsa => new AlgorithmIdentifier(Oids.Sha256WithRsaEncryption, HasNullParameters: true),
        SignatureAlgorithm.Sha384WithRsa => new AlgorithmIdentifier(Oids.Sha384WithRsaEncryption, HasNullParameters: true),
        SignatureAlgorithm.Sha512WithRsa => new AlgorithmIdentifier(Oids.Sha512WithRsaEncryption, HasNullParameters: true),
        SignatureAlgorithm.EcdsaWithSha256 => new AlgorithmIdentifier(Oids.EcdsaWithSha256, HasNullParameters: false),
        SignatureAlgorithm.EcdsaWithSha384 => new AlgorithmIdentifier(Oids.EcdsaWithSha384, HasNullParameters: false),
        SignatureAlgorithm.EcdsaWithSha512 => new AlgorithmIdentifier(Oids.EcdsaWithSha512, HasNullParameters: false),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported signature algorithm."),
    };

    public void Encode(AsnWriter writer)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier(Oid);

        if (HasNullParameters)
        {
            writer.WriteNull();
        }

        writer.PopSequence();
    }

    public byte[] Encode()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        Encode(writer);
        return writer.Encode();
    }
}
