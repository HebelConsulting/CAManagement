namespace CAManagement.X509.Ocsp;

public enum OcspCertStatus
{
    Good,
    Revoked,
    Unknown,
}

/// <summary>One RFC 6960 SingleResponse: the status of one certificate.</summary>
public sealed record OcspSingleResponse(
    OcspCertId CertId,
    OcspCertStatus Status,
    DateTimeOffset ThisUpdate,
    DateTimeOffset? NextUpdate = null,
    DateTimeOffset? RevocationTime = null,
    RevocationReason? RevocationReason = null)
{
    public static OcspSingleResponse Good(OcspCertId certId, DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate = null) =>
        new(certId, OcspCertStatus.Good, thisUpdate, nextUpdate);

    public static OcspSingleResponse Revoked(OcspCertId certId, DateTimeOffset thisUpdate, DateTimeOffset revocationTime,
        RevocationReason? reason = null, DateTimeOffset? nextUpdate = null) =>
        new(certId, OcspCertStatus.Revoked, thisUpdate, nextUpdate, revocationTime, reason);

    public static OcspSingleResponse Unknown(OcspCertId certId, DateTimeOffset thisUpdate) =>
        new(certId, OcspCertStatus.Unknown, thisUpdate);
}
