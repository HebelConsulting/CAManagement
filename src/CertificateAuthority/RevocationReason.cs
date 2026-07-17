namespace CertificateAuthority;

/// <summary>RFC 5280 §5.3.1 CRLReason (ENUMERATED; value 7 is unused by the RFC).</summary>
public enum RevocationReason
{
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}
