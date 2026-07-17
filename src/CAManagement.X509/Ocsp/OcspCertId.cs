using System.Formats.Asn1;
using System.Security.Cryptography;

namespace CAManagement.X509.Ocsp;

/// <summary>
/// RFC 6960 CertID: identifies a certificate towards an OCSP responder by hashes
/// of the issuer's name and public key plus the certificate serial.
/// </summary>
public sealed record OcspCertId(string HashAlgorithmOid, byte[] IssuerNameHash, byte[] IssuerKeyHash, byte[] SerialNumber)
{
    public static OcspCertId Create(
        HashAlgorithmName hashAlgorithm, byte[] issuerNameDer, SubjectPublicKeyInfo issuerPublicKey, byte[] serialNumber) =>
        new(OidFor(hashAlgorithm),
            Hash(hashAlgorithm, issuerNameDer),
            Hash(hashAlgorithm, issuerPublicKey.PublicKeyBytes),
            Der.TrimLeadingZeros(serialNumber).ToArray());

    /// <summary>
    /// Does this CertID refer to the given issuer? Recomputes the name/key hashes
    /// with this CertID's own hash algorithm (the serial is not considered).
    /// Throws <see cref="NotSupportedException"/> for unsupported hash algorithms.
    /// </summary>
    public bool MatchesIssuer(byte[] issuerNameDer, SubjectPublicKeyInfo issuerPublicKey)
    {
        var hashAlgorithm = HashAlgorithmFromOid(HashAlgorithmOid);

        return IssuerNameHash.AsSpan().SequenceEqual(Hash(hashAlgorithm, issuerNameDer))
            && IssuerKeyHash.AsSpan().SequenceEqual(Hash(hashAlgorithm, issuerPublicKey.PublicKeyBytes));
    }

    /// <summary>Same certificate identified with the same hash algorithm?</summary>
    public bool Matches(OcspCertId other) =>
        HashAlgorithmOid == other.HashAlgorithmOid
        && IssuerNameHash.AsSpan().SequenceEqual(other.IssuerNameHash)
        && IssuerKeyHash.AsSpan().SequenceEqual(other.IssuerKeyHash)
        && SerialNumber.AsSpan().SequenceEqual(other.SerialNumber);

    internal void Encode(AsnWriter writer)
    {
        writer.PushSequence();

        writer.PushSequence();
        writer.WriteObjectIdentifier(HashAlgorithmOid);
        writer.WriteNull(); // digest AlgorithmIdentifiers carry NULL in practice (matches openssl)
        writer.PopSequence();

        writer.WriteOctetString(IssuerNameHash);
        writer.WriteOctetString(IssuerKeyHash);
        writer.WriteIntegerUnsigned(Der.TrimLeadingZeros(SerialNumber));
        writer.PopSequence();
    }

    internal static OcspCertId Decode(AsnReader reader)
    {
        var certId = reader.ReadSequence();

        var algorithm = certId.ReadSequence();
        var hashOid = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData)
        {
            algorithm.ReadNull();
        }

        var issuerNameHash = certId.ReadOctetString();
        var issuerKeyHash = certId.ReadOctetString();
        var serialNumber = Der.TrimLeadingZeros(certId.ReadIntegerBytes().Span).ToArray();
        certId.ThrowIfNotEmpty();

        return new OcspCertId(hashOid, issuerNameHash, issuerKeyHash, serialNumber);
    }

    private static string OidFor(HashAlgorithmName hashAlgorithm) => hashAlgorithm.Name switch
    {
        "SHA1" => Oids.Sha1,
        "SHA256" => Oids.Sha256,
        "SHA384" => Oids.Sha384,
        "SHA512" => Oids.Sha512,
        var other => throw new NotSupportedException($"Unsupported CertID hash algorithm '{other}'."),
    };

    private static HashAlgorithmName HashAlgorithmFromOid(string oid) => oid switch
    {
        Oids.Sha1 => HashAlgorithmName.SHA1,
        Oids.Sha256 => HashAlgorithmName.SHA256,
        Oids.Sha384 => HashAlgorithmName.SHA384,
        Oids.Sha512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Unsupported CertID hash algorithm OID {oid}."),
    };

    private static byte[] Hash(HashAlgorithmName hashAlgorithm, byte[] data) => hashAlgorithm.Name switch
    {
        "SHA1" => SHA1.HashData(data),
        "SHA256" => SHA256.HashData(data),
        "SHA384" => SHA384.HashData(data),
        "SHA512" => SHA512.HashData(data),
        var other => throw new NotSupportedException($"Unsupported CertID hash algorithm '{other}'."),
    };
}
