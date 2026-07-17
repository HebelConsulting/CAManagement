namespace CAManagement.X509;

/// <summary>
/// One certificatePolicies entry (RFC 5280 §4.2.1.4): the policy OID with
/// optional CPS-URI and user-notice qualifiers. <paramref name="UserNotice"/>
/// becomes the explicitText (noticeRef is intentionally unsupported — RFC 5280
/// discourages it and CAs do not use it).
/// </summary>
public sealed record PolicyInformation(string PolicyOid, string? CpsUri = null, string? UserNotice = null);
