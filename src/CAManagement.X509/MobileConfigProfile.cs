using System.Security;
using System.Text;

namespace CAManagement.X509;

/// <summary>
/// Builds an Apple configuration profile (<c>.mobileconfig</c>) carrying certificate payloads — the
/// distribution format that installs an S/MIME identity (PKCS#12) and/or trusted root certificates on
/// iOS/iPadOS/macOS in one tap. Lives in this library so consumers stop hand-rolling the plist: the
/// SimplArchiveEncryption identity tool carried the first copy, the caconsole <c>mobileconfig</c> verb
/// would have been the second.
/// </summary>
/// <remarks>
/// A PKCS#12 payload embeds its password so the install does not prompt. That is a deliberate,
/// documented trade for hand-delivered profiles: whoever holds the file holds the identity. Enrollment
/// flows that must not embed the password should ship the certificate payloads only and deliver the
/// PKCS#12 separately.
/// </remarks>
public sealed class MobileConfigProfile(string displayName, string identifier)
{
    private readonly List<string> _payloads = [];

    /// <summary>Adds a PKCS#12 identity payload (<c>com.apple.security.pkcs12</c>).</summary>
    public MobileConfigProfile AddIdentity(byte[] pkcs12, string password, string displayName, string identifier)
    {
        _payloads.Add(Payload("com.apple.security.pkcs12", displayName, identifier,
            $"        <key>Password</key><string>{Escape(password)}</string>\n"
            + $"        <key>PayloadContent</key>\n        <data>{Convert.ToBase64String(pkcs12)}</data>\n"));
        return this;
    }

    /// <summary>Adds a trusted root certificate payload (<c>com.apple.security.root</c>), DER bytes.</summary>
    public MobileConfigProfile AddRootCertificate(byte[] certificateDer, string displayName, string identifier)
    {
        _payloads.Add(Payload("com.apple.security.root", displayName, identifier,
            $"        <key>PayloadContent</key>\n        <data>{Convert.ToBase64String(certificateDer)}</data>\n"));
        return this;
    }

    /// <summary>The profile XML. At least one payload must have been added.</summary>
    public string Build()
    {
        if (_payloads.Count == 0)
        {
            throw new InvalidOperationException("A configuration profile needs at least one payload.");
        }

        var builder = new StringBuilder();
        builder.Append($"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>PayloadContent</key>
                <array>

            """);
        foreach (var payload in _payloads)
        {
            builder.Append(payload);
        }

        builder.Append($"""
                </array>
                <key>PayloadType</key><string>Configuration</string>
                <key>PayloadVersion</key><integer>1</integer>
                <key>PayloadIdentifier</key><string>{Escape(identifier)}</string>
                <key>PayloadUUID</key><string>{NewUuid()}</string>
                <key>PayloadDisplayName</key><string>{Escape(displayName)}</string>
            </dict>
            </plist>
            """);
        return builder.ToString();
    }

    private static string Payload(string type, string displayName, string identifier, string body) =>
        $"        <dict>\n"
        + $"        <key>PayloadType</key><string>{type}</string>\n"
        + "        <key>PayloadVersion</key><integer>1</integer>\n"
        + $"        <key>PayloadIdentifier</key><string>{Escape(identifier)}</string>\n"
        + $"        <key>PayloadUUID</key><string>{NewUuid()}</string>\n"
        + $"        <key>PayloadDisplayName</key><string>{Escape(displayName)}</string>\n"
        + body
        + "        </dict>\n";

    private static string NewUuid() => Guid.NewGuid().ToString().ToUpperInvariant();

    private static string Escape(string value) => SecurityElement.Escape(value);
}
