using System.Formats.Asn1;

namespace CAManagement.X509;

/// <summary>Packages certificates for distribution (chain files, trust stores).</summary>
public static class CertificateBundle
{
    public static string ToPemBundle(IReadOnlyList<byte[]> certificatesDer) =>
        string.Join("\n", certificatesDer.Select(der => Pem.Encode("CERTIFICATE", der))) + "\n";

    /// <summary>
    /// A certs-only ("degenerate") CMS SignedData — the classic .p7b bundle
    /// (RFC 5652 §5.2): no signers, no digests, just the certificate set.
    /// </summary>
    public static byte[] ToPkcs7(IReadOnlyList<byte[]> certificatesDer)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        writer.PushSequence(); // ContentInfo
        writer.WriteObjectIdentifier(Analysis.OidNames.Pkcs7SignedData);

        var contentTag = new Asn1Tag(TagClass.ContextSpecific, 0);
        writer.PushSequence(contentTag);
        writer.PushSequence(); // SignedData

        writer.WriteInteger(1); // version

        writer.PushSetOf(); // digestAlgorithms: empty
        writer.PopSetOf();

        writer.PushSequence(); // encapContentInfo: data, no content
        writer.WriteObjectIdentifier(Analysis.OidNames.Pkcs7Data);
        writer.PopSequence();

        var certificatesTag = new Asn1Tag(TagClass.ContextSpecific, 0);
        writer.PushSetOf(certificatesTag); // certificates [0] IMPLICIT CertificateSet
        foreach (var certificateDer in certificatesDer)
        {
            writer.WriteEncodedValue(certificateDer);
        }
        writer.PopSetOf(certificatesTag);

        writer.PushSetOf(); // signerInfos: empty
        writer.PopSetOf();

        writer.PopSequence(); // SignedData
        writer.PopSequence(contentTag);
        writer.PopSequence(); // ContentInfo

        return writer.Encode();
    }
}
