namespace CertificateAuthority.Analysis;

public enum DocumentKind
{
    Unknown,
    Certificate,
    CertificationRequest,
    CertificateList,
    SubjectPublicKeyInfo,
    Pkcs8PrivateKey,
    RsaPrivateKey,
    EcPrivateKey,
}
