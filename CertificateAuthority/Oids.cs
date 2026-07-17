namespace CertificateAuthority;

/// <summary>Object identifiers used by the CA library (dotted-decimal form).</summary>
public static class Oids
{
    // Public key algorithms
    public const string RsaEncryption = "1.2.840.113549.1.1.1";
    public const string EcPublicKey = "1.2.840.10045.2.1";

    // Signature algorithms
    public const string Sha256WithRsaEncryption = "1.2.840.113549.1.1.11";
    public const string Sha384WithRsaEncryption = "1.2.840.113549.1.1.12";
    public const string Sha512WithRsaEncryption = "1.2.840.113549.1.1.13";
    public const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";
    public const string EcdsaWithSha384 = "1.2.840.10045.4.3.3";
    public const string EcdsaWithSha512 = "1.2.840.10045.4.3.4";

    // Named curves
    public const string Prime256V1 = "1.2.840.10045.3.1.7";
    public const string Secp384R1 = "1.3.132.0.34";
    public const string Secp521R1 = "1.3.132.0.35";

    // PKCS#9 attributes
    public const string ExtensionRequest = "1.2.840.113549.1.9.14";

    // X.500 attribute types
    public const string CommonName = "2.5.4.3";
    public const string SerialNumberAttribute = "2.5.4.5";
    public const string Country = "2.5.4.6";
    public const string Locality = "2.5.4.7";
    public const string StateOrProvince = "2.5.4.8";
    public const string Organization = "2.5.4.10";
    public const string OrganizationalUnit = "2.5.4.11";
    public const string DomainComponent = "0.9.2342.19200300.100.1.25";
    public const string EmailAddress = "1.2.840.113549.1.9.1";

    // Extended key usage purposes
    public const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";
    public const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";

    // Certificate extensions
    public const string SubjectKeyIdentifier = "2.5.29.14";
    public const string KeyUsage = "2.5.29.15";
    public const string SubjectAlternativeName = "2.5.29.17";
    public const string BasicConstraints = "2.5.29.19";
    public const string CrlNumber = "2.5.29.20";
    public const string CrlReasonCode = "2.5.29.21";
    public const string CrlDistributionPoints = "2.5.29.31";
    public const string AuthorityKeyIdentifier = "2.5.29.35";
    public const string ExtendedKeyUsage = "2.5.29.37";
}
