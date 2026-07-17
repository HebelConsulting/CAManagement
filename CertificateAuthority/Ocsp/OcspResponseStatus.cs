namespace CertificateAuthority.Ocsp;

/// <summary>RFC 6960 OCSPResponseStatus (value 4 is unused by the RFC).</summary>
public enum OcspResponseStatus
{
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}
