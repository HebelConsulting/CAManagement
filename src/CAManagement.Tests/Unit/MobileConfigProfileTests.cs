using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using CAManagement.X509;

namespace CAManagement.Tests.Unit;

/// <summary>
/// The .mobileconfig builder: a valid plist whose payloads round-trip their bytes, with every
/// caller-supplied string XML-escaped — the profile is handed to a device parser, so "it looks right"
/// is not the bar; parsing it back is.
/// </summary>
public sealed class MobileConfigProfileTests
{
    [Fact]
    public void Identity_and_roots_round_trip_through_a_parseable_plist()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=profile@example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var pkcs12 = certificate.Export(X509ContentType.Pkcs12, "p12-secret");
        var rootDer = certificate.Export(X509ContentType.Cert);

        var xml = new MobileConfigProfile("Test & <Profile>", "test.profile")
            .AddIdentity(pkcs12, "p12-secret", "Identity <1>", "test.profile.identity")
            .AddRootCertificate(rootDer, "Root & anchor", "test.profile.root1")
            .Build();

        var document = new XmlDocument { XmlResolver = null };
        document.LoadXml(xml); // throws on malformed XML — escaping bugs die here

        var payloads = document.SelectNodes("/plist/dict/array/dict")!;
        Assert.Equal(2, payloads.Count);

        var types = document.SelectNodes("/plist/dict/array/dict/key[text()='PayloadType']/following-sibling::string[1]")!;
        Assert.Equal(["com.apple.security.pkcs12", "com.apple.security.root"],
            types.Cast<XmlNode>().Select(n => n.InnerText).ToArray());

        // The embedded bytes survive base64 exactly — a device installs what the caller supplied.
        var datas = document.SelectNodes("//data")!.Cast<XmlNode>().ToArray();
        Assert.Equal(pkcs12, Convert.FromBase64String(datas[0].InnerText.Trim()));
        Assert.Equal(rootDer, Convert.FromBase64String(datas[1].InnerText.Trim()));

        // The password rides inside the identity payload (the documented hand-delivery trade).
        var password = document.SelectSingleNode("//key[text()='Password']/following-sibling::string[1]")!;
        Assert.Equal("p12-secret", password.InnerText);

        // The hostile display name arrived escaped, and parses back to the original.
        var displayName = document.SelectSingleNode("/plist/dict/key[text()='PayloadDisplayName']/following-sibling::string[1]")!;
        Assert.Equal("Test & <Profile>", displayName.InnerText);
    }

    [Fact]
    public void An_empty_profile_is_refused()
    {
        Assert.Throws<InvalidOperationException>(() => new MobileConfigProfile("Empty", "test.empty").Build());
    }
}
