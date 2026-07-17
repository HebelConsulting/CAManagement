using System.Formats.Asn1;

namespace CertificateAuthority;

/// <summary>Factories for the RFC 5280 extensions in v1 scope.</summary>
public static class CertificateExtensions
{
    /// <summary>Critical per RFC 5280 §4.2.1.9 (required critical on CA certificates).</summary>
    public static CertificateExtension BasicConstraints(bool isCa, int? pathLengthConstraint = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        if (isCa) // DEFAULT FALSE
        {
            writer.WriteBoolean(true);
        }

        if (pathLengthConstraint is { } pathLength)
        {
            writer.WriteInteger(pathLength);
        }

        writer.PopSequence();

        return new CertificateExtension(Oids.BasicConstraints, Critical: true, writer.Encode());
    }

    public static CertificateExtension KeyUsage(KeyUsages usages)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteNamedBitList(usages);

        return new CertificateExtension(Oids.KeyUsage, Critical: true, writer.Encode());
    }

    public static CertificateExtension SubjectKeyIdentifier(byte[] keyIdentifier)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(keyIdentifier);

        return new CertificateExtension(Oids.SubjectKeyIdentifier, Critical: false, writer.Encode());
    }

    /// <summary>Uses the keyIdentifier [0] form only (the issuer's subject key identifier).</summary>
    public static CertificateExtension AuthorityKeyIdentifier(byte[] keyIdentifier)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteOctetString(keyIdentifier, new Asn1Tag(TagClass.ContextSpecific, 0));
        writer.PopSequence();

        return new CertificateExtension(Oids.AuthorityKeyIdentifier, Critical: false, writer.Encode());
    }

    /// <summary>RFC 5280 §5.2.3 CRLNumber (monotonically increasing per CRL scope).</summary>
    public static CertificateExtension CrlNumber(ulong value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteInteger(value);

        return new CertificateExtension(Oids.CrlNumber, Critical: false, writer.Encode());
    }

    public static CertificateExtension ExtendedKeyUsage(params string[] purposeOids)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        foreach (var oid in purposeOids)
        {
            writer.WriteObjectIdentifier(oid);
        }

        writer.PopSequence();

        return new CertificateExtension(Oids.ExtendedKeyUsage, Critical: false, writer.Encode());
    }

    public static CertificateExtension SubjectAlternativeDnsNames(params string[] dnsNames)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        foreach (var dnsName in dnsNames)
        {
            // GeneralName dNSName [2] IMPLICIT IA5String
            writer.WriteCharacterString(UniversalTagNumber.IA5String, dnsName, new Asn1Tag(TagClass.ContextSpecific, 2));
        }

        writer.PopSequence();

        return new CertificateExtension(Oids.SubjectAlternativeName, Critical: false, writer.Encode());
    }
}
