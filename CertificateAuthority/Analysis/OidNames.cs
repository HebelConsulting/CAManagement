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
    };

    public static string? For(string oid) => Names.GetValueOrDefault(oid);
}
