using System.Formats.Asn1;
using System.Security.Cryptography;

namespace CAManagement.X509;

/// <summary>
/// RFC 5280 SubjectPublicKeyInfo: <c>SEQUENCE { algorithm AlgorithmIdentifier,
/// subjectPublicKey BIT STRING }</c>. RSA keys carry a PKCS#1 RSAPublicKey in the
/// bit string; EC keys carry the uncompressed point with the named curve as the
/// algorithm parameter.
/// </summary>
public sealed class SubjectPublicKeyInfo
{
    private readonly string _algorithmOid;

    private readonly string? _namedCurveOid; // EC only; RSA uses explicit NULL parameters

    /// <summary>The content of the subjectPublicKey BIT STRING.</summary>
    public byte[] PublicKeyBytes { get; }

    /// <summary>
    /// The public key ALGORITHM — <see cref="Oids.RsaEncryption"/> or <see cref="Oids.EcPublicKey"/>.
    /// </summary>
    /// <remarks>
    /// Exposed because the right keyUsage for a DECRYPTION certificate depends on it and on nothing else:
    /// key transport (RSA) needs <c>keyEncipherment</c>, key agreement (EC) needs <c>keyAgreement</c>, and
    /// naming the wrong one produces a certificate that works everywhere except where it is checked (#18).
    /// A caller states the purpose; this is what lets the answer be derived rather than guessed.
    /// </remarks>
    public string AlgorithmOid => _algorithmOid;

    private SubjectPublicKeyInfo(string algorithmOid, string? namedCurveOid, byte[] publicKeyBytes)
    {
        _algorithmOid = algorithmOid;
        _namedCurveOid = namedCurveOid;
        PublicKeyBytes = publicKeyBytes;
    }

    public static SubjectPublicKeyInfo FromRsa(byte[] modulus, byte[] publicExponent)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteIntegerUnsigned(Der.TrimLeadingZeros(modulus));
        writer.WriteIntegerUnsigned(Der.TrimLeadingZeros(publicExponent));
        writer.PopSequence();

        return new SubjectPublicKeyInfo(Oids.RsaEncryption, namedCurveOid: null, writer.Encode());
    }

    /// <param name="uncompressedPoint">The raw EC point, <c>0x04 || X || Y</c>.</param>
    public static SubjectPublicKeyInfo FromEc(string namedCurveOid, byte[] uncompressedPoint) =>
        new(Oids.EcPublicKey, namedCurveOid, uncompressedPoint);

    public static SubjectPublicKeyInfo Decode(byte[] der)
    {
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var spki = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        var algorithm = spki.ReadSequence();
        var algorithmOid = algorithm.ReadObjectIdentifier();

        string? namedCurveOid = null;
        switch (algorithmOid)
        {
            case Oids.RsaEncryption:
                if (algorithm.HasData)
                {
                    algorithm.ReadNull();
                }
                break;
            case Oids.EcPublicKey:
                namedCurveOid = algorithm.ReadObjectIdentifier();
                break;
            default:
                throw new NotSupportedException($"Unsupported public key algorithm OID {algorithmOid}.");
        }

        algorithm.ThrowIfNotEmpty();
        var keyBits = spki.ReadBitString(out var unusedBits);
        spki.ThrowIfNotEmpty();

        return unusedBits == 0
            ? new SubjectPublicKeyInfo(algorithmOid, namedCurveOid, keyBits)
            : throw new NotSupportedException("subjectPublicKey BIT STRING with unused bits is not supported.");
    }

    /// <summary>RFC 5280 §4.2.1.2 method 1: SHA-1 over the subjectPublicKey bits.</summary>
    public byte[] ComputeKeyIdentifier() => SHA1.HashData(PublicKeyBytes);

    public void Encode(AsnWriter writer)
    {
        writer.PushSequence();

        writer.PushSequence();
        writer.WriteObjectIdentifier(_algorithmOid);
        if (_namedCurveOid is { } curveOid)
        {
            writer.WriteObjectIdentifier(curveOid);
        }
        else
        {
            writer.WriteNull();
        }
        writer.PopSequence();

        writer.WriteBitString(PublicKeyBytes);
        writer.PopSequence();
    }

    public byte[] Encode()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        Encode(writer);
        return writer.Encode();
    }
}
