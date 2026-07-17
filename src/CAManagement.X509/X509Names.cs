using System.Formats.Asn1;
using System.Text;
using CAManagement.X509.Analysis;

namespace CAManagement.X509;

/// <summary>
/// Extracts subject/issuer names from any supported input (certificate, PKCS#10
/// CSR, CRL — PEM or DER), e.g. to obtain the CRL issuer from a CA certificate.
/// Names are read positionally without signature verification; decoded
/// components keep their original string types, so re-encoding is byte-faithful.
/// </summary>
public static class X509Names
{
    /// <summary>The subject of a certificate or CSR.</summary>
    public static DistinguishedName SubjectOf(byte[] input)
    {
        var (kind, der) = Classify(input);

        return kind switch
        {
            DocumentKind.Certificate => ReadFromTbsCertificate(der, wantIssuer: false),
            DocumentKind.CertificationRequest => ReadFromCertificationRequest(der),
            _ => throw new NotSupportedException($"A {kind} document has no subject name to extract."),
        };
    }

    /// <summary>The issuer of a certificate or CRL.</summary>
    public static DistinguishedName IssuerOf(byte[] input)
    {
        var (kind, der) = Classify(input);

        return kind switch
        {
            DocumentKind.Certificate => ReadFromTbsCertificate(der, wantIssuer: true),
            DocumentKind.CertificateList => ReadFromTbsCertList(der),
            _ => throw new NotSupportedException($"A {kind} document has no issuer name to extract."),
        };
    }

    private static (DocumentKind Kind, byte[] Der) Classify(byte[] input)
    {
        string? label = null;
        var der = input;

        if (input.AsSpan().IndexOf("-----BEGIN"u8) >= 0)
        {
            (label, der) = Pem.TryDecodeFirst(Encoding.UTF8.GetString(input))
                ?? throw new FormatException("No PEM block found in the input.");
        }

        return (Asn1Analyzer.AnalyzeDer(der, label).Kind, der);
    }

    private static DistinguishedName ReadFromTbsCertificate(byte[] der, bool wantIssuer)
    {
        var tbs = new AsnReader(der, AsnEncodingRules.DER).ReadSequence().ReadSequence();

        if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            tbs.ReadEncodedValue(); // version
        }

        tbs.ReadEncodedValue(); // serialNumber
        tbs.ReadEncodedValue(); // signature AlgorithmIdentifier

        var issuer = DistinguishedName.Decode(tbs);
        if (wantIssuer)
        {
            return issuer;
        }

        tbs.ReadEncodedValue(); // validity

        return DistinguishedName.Decode(tbs);
    }

    private static DistinguishedName ReadFromCertificationRequest(byte[] der)
    {
        var requestInfo = new AsnReader(der, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        requestInfo.ReadEncodedValue(); // version

        return DistinguishedName.Decode(requestInfo);
    }

    private static DistinguishedName ReadFromTbsCertList(byte[] der)
    {
        var tbs = new AsnReader(der, AsnEncodingRules.DER).ReadSequence().ReadSequence();

        if (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
        {
            tbs.ReadEncodedValue(); // version
        }

        tbs.ReadEncodedValue(); // signature AlgorithmIdentifier

        return DistinguishedName.Decode(tbs);
    }
}
