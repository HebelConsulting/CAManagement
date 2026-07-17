namespace CAManagement.X509;

/// <summary>One revokedCertificates entry: the serial as a big-endian positive integer.</summary>
public sealed record RevokedCertificate(
    byte[] SerialNumber,
    DateTimeOffset RevocationDate,
    RevocationReason? Reason = null);
