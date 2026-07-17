using System.Formats.Asn1;

namespace CAManagement.X509;

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

    public static CertificateExtension SubjectAlternativeDnsNames(params string[] dnsNames) =>
        SubjectAlternativeName(dnsNames.Select(GeneralName.Dns).ToArray());

    public static CertificateExtension SubjectAlternativeName(params GeneralName[] names) =>
        new(Oids.SubjectAlternativeName, Critical: false, EncodeGeneralNames(names));

    public static CertificateExtension IssuerAlternativeName(params GeneralName[] names) =>
        new(Oids.IssuerAlternativeName, Critical: false, EncodeGeneralNames(names));

    /// <summary>One DistributionPoint whose fullName lists the given URIs (RFC 5280 §4.2.1.13).</summary>
    public static CertificateExtension CrlDistributionPoints(params string[] uris)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        writer.PushSequence(); // DistributionPoint
        var distributionPointTag = new Asn1Tag(TagClass.ContextSpecific, 0);
        writer.PushSequence(distributionPointTag); // distributionPoint [0]
        var fullNameTag = new Asn1Tag(TagClass.ContextSpecific, 0);
        writer.PushSequence(fullNameTag); // fullName [0] GeneralNames

        foreach (var uri in uris)
        {
            GeneralName.Uri(uri).Encode(writer);
        }

        writer.PopSequence(fullNameTag);
        writer.PopSequence(distributionPointTag);
        writer.PopSequence();

        writer.PopSequence();

        return new CertificateExtension(Oids.CrlDistributionPoints, Critical: false, writer.Encode());
    }

    /// <summary>authorityInfoAccess with OCSP and/or caIssuers URIs (RFC 5280 §4.2.2.1).</summary>
    public static CertificateExtension AuthorityInfoAccess(string? ocspUri = null, string? caIssuersUri = null)
    {
        if (ocspUri is null && caIssuersUri is null)
        {
            throw new ArgumentException("At least one of ocspUri and caIssuersUri is required.");
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        WriteAccessDescription(writer, Oids.AccessMethodOcsp, ocspUri);
        WriteAccessDescription(writer, Oids.AccessMethodCaIssuers, caIssuersUri);

        writer.PopSequence();

        return new CertificateExtension(Oids.AuthorityInfoAccess, Critical: false, writer.Encode());
    }

    /// <summary>certificatePolicies with plain policy OIDs (no qualifiers).</summary>
    public static CertificateExtension CertificatePolicies(params string[] policyOids) =>
        CertificatePolicies(policyOids.Select(oid => new PolicyInformation(oid)).ToArray());

    /// <summary>certificatePolicies with optional CPS-URI and user-notice qualifiers per policy.</summary>
    public static CertificateExtension CertificatePolicies(params PolicyInformation[] policies)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        foreach (var policy in policies)
        {
            writer.PushSequence();
            writer.WriteObjectIdentifier(policy.PolicyOid);

            if (policy.CpsUri is not null || policy.UserNotice is not null)
            {
                writer.PushSequence(); // policyQualifiers

                if (policy.CpsUri is { } cpsUri)
                {
                    writer.PushSequence();
                    writer.WriteObjectIdentifier(Oids.CpsQualifier);
                    writer.WriteCharacterString(UniversalTagNumber.IA5String, cpsUri);
                    writer.PopSequence();
                }

                if (policy.UserNotice is { } userNotice)
                {
                    writer.PushSequence();
                    writer.WriteObjectIdentifier(Oids.UserNoticeQualifier);
                    writer.PushSequence(); // UserNotice
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, userNotice); // explicitText
                    writer.PopSequence();
                    writer.PopSequence();
                }

                writer.PopSequence();
            }

            writer.PopSequence();
        }

        writer.PopSequence();

        return new CertificateExtension(Oids.CertificatePolicies, Critical: false, writer.Encode());
    }

    private static void WriteAccessDescription(AsnWriter writer, string accessMethodOid, string? uri)
    {
        if (uri is null)
        {
            return;
        }

        writer.PushSequence();
        writer.WriteObjectIdentifier(accessMethodOid);
        GeneralName.Uri(uri).Encode(writer);
        writer.PopSequence();
    }

    private static byte[] EncodeGeneralNames(IReadOnlyList<GeneralName> names)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        foreach (var name in names)
        {
            name.Encode(writer);
        }

        writer.PopSequence();

        return writer.Encode();
    }
}
