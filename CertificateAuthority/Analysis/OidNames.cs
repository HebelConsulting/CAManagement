namespace CertificateAuthority.Analysis;

/// <summary>Friendly names for OIDs commonly seen in CA-related structures.</summary>
public static class OidNames
{
    private static readonly Dictionary<string, string> Names = new()
    {
        // Public key algorithms
        [Oids.RsaEncryption] = "rsaEncryption",
        [Oids.EcPublicKey] = "ecPublicKey",
        ["1.2.840.10040.4.1"] = "dsa",

        // Signature algorithms
        [Oids.Sha256WithRsaEncryption] = "sha256WithRSAEncryption",
        [Oids.Sha384WithRsaEncryption] = "sha384WithRSAEncryption",
        [Oids.Sha512WithRsaEncryption] = "sha512WithRSAEncryption",
        ["1.2.840.113549.1.1.5"] = "sha1WithRSAEncryption",
        [Oids.EcdsaWithSha256] = "ecdsa-with-SHA256",
        [Oids.EcdsaWithSha384] = "ecdsa-with-SHA384",
        [Oids.EcdsaWithSha512] = "ecdsa-with-SHA512",

        // Digests
        ["1.3.14.3.2.26"] = "sha1",
        ["2.16.840.1.101.3.4.2.1"] = "sha256",
        ["2.16.840.1.101.3.4.2.2"] = "sha384",
        ["2.16.840.1.101.3.4.2.3"] = "sha512",

        // Named curves
        [Oids.Prime256V1] = "prime256v1",
        [Oids.Secp384R1] = "secp384r1",
        [Oids.Secp521R1] = "secp521r1",

        // Edwards / Montgomery curve algorithms (RFC 8410)
        [Oids.X25519] = "X25519",
        [Oids.X448] = "X448",
        [Oids.Ed25519] = "Ed25519",
        [Oids.Ed448] = "Ed448",

        // X.500 attribute types
        [Oids.CommonName] = "commonName",
        [Oids.SerialNumberAttribute] = "serialNumber",
        [Oids.Country] = "countryName",
        [Oids.Locality] = "localityName",
        [Oids.StateOrProvince] = "stateOrProvinceName",
        [Oids.Organization] = "organizationName",
        [Oids.OrganizationalUnit] = "organizationalUnitName",
        [Oids.DomainComponent] = "domainComponent",
        [Oids.EmailAddress] = "emailAddress",

        // Extensions
        [Oids.SubjectKeyIdentifier] = "subjectKeyIdentifier",
        [Oids.KeyUsage] = "keyUsage",
        [Oids.SubjectAlternativeName] = "subjectAltName",
        [Oids.BasicConstraints] = "basicConstraints",
        [Oids.CrlNumber] = "cRLNumber",
        [Oids.CrlReasonCode] = "cRLReason",
        [Oids.CrlDistributionPoints] = "cRLDistributionPoints",
        [Oids.AuthorityKeyIdentifier] = "authorityKeyIdentifier",
        [Oids.ExtendedKeyUsage] = "extKeyUsage",
        ["2.5.29.30"] = "nameConstraints",
        ["2.5.29.32"] = "certificatePolicies",
        ["2.5.29.36"] = "policyConstraints",
        ["1.3.6.1.5.5.7.1.1"] = "authorityInfoAccess",
        ["1.3.6.1.5.5.7.48.1"] = "ocsp",
        ["1.3.6.1.5.5.7.48.2"] = "caIssuers",
        [Oids.OcspBasicResponse] = "id-pkix-ocsp-basic",
        [Oids.OcspNonce] = "id-pkix-ocsp-nonce",

        // EKU purposes
        [Oids.ServerAuthentication] = "serverAuth",
        [Oids.ClientAuthentication] = "clientAuth",
        ["1.3.6.1.5.5.7.3.3"] = "codeSigning",
        ["1.3.6.1.5.5.7.3.4"] = "emailProtection",
        ["1.3.6.1.5.5.7.3.8"] = "timeStamping",
        ["1.3.6.1.5.5.7.3.9"] = "OCSPSigning",

        // PKCS#9 attributes
        [Oids.ExtensionRequest] = "extensionRequest",
        ["1.2.840.113549.1.9.7"] = "challengePassword",
        ["1.2.840.113549.1.9.3"] = "contentType",
        ["1.2.840.113549.1.9.4"] = "messageDigest",
        ["1.2.840.113549.1.9.5"] = "signingTime",
        ["1.2.840.113549.1.9.20"] = "friendlyName",
        ["1.2.840.113549.1.9.21"] = "localKeyID",

        // PKCS#7 / CMS content types
        [Pkcs7Data] = "pkcs7-data",
        [Pkcs7SignedData] = "pkcs7-signedData",
        ["1.2.840.113549.1.7.3"] = "pkcs7-envelopedData",
        ["1.2.840.113549.1.7.5"] = "pkcs7-digestedData",
        [Pkcs7EncryptedData] = "pkcs7-encryptedData",

        // PKCS#12 bag types
        ["1.2.840.113549.1.12.10.1.1"] = "keyBag",
        [Pkcs8ShroudedKeyBag] = "pkcs8ShroudedKeyBag",
        [CertBag] = "certBag",
        ["1.2.840.113549.1.12.10.1.4"] = "crlBag",
        ["1.2.840.113549.1.12.10.1.5"] = "secretBag",
        ["1.2.840.113549.1.12.10.1.6"] = "safeContentsBag",
        ["1.2.840.113549.1.9.22.1"] = "x509Certificate",
        ["1.2.840.113549.1.9.23.1"] = "x509Crl",

        // Password-based encryption
        [Pbes2] = "PBES2",
        [Pbkdf2] = "PBKDF2",
        ["1.2.840.113549.1.12.1.3"] = "pbeWithSHAAnd3-KeyTripleDES-CBC",
        ["1.2.840.113549.1.12.1.6"] = "pbeWithSHAAnd40BitRC2-CBC",
        ["1.2.840.113549.3.7"] = "des-EDE3-CBC",
        ["2.16.840.1.101.3.4.1.2"] = "aes128-CBC",
        ["2.16.840.1.101.3.4.1.22"] = "aes192-CBC",
        ["2.16.840.1.101.3.4.1.42"] = "aes256-CBC",
        ["1.2.840.113549.2.7"] = "hmacWithSHA1",
        ["1.2.840.113549.2.9"] = "hmacWithSHA256",
        ["1.2.840.113549.2.10"] = "hmacWithSHA384",
        ["1.2.840.113549.2.11"] = "hmacWithSHA512",
    };

    // OIDs the analyzer dispatches on (not in the certificate-issuing Oids registry).
    public const string Pkcs7Data = "1.2.840.113549.1.7.1";
    public const string Pkcs7SignedData = "1.2.840.113549.1.7.2";
    public const string Pkcs7EncryptedData = "1.2.840.113549.1.7.6";
    public const string Pkcs8ShroudedKeyBag = "1.2.840.113549.1.12.10.1.2";
    public const string CertBag = "1.2.840.113549.1.12.10.1.3";
    public const string Pbes2 = "1.2.840.113549.1.5.13";
    public const string Pbkdf2 = "1.2.840.113549.1.5.12";

    public static string? For(string oid) => Names.GetValueOrDefault(oid);
}
