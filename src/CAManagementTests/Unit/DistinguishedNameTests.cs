using System.Security.Cryptography.X509Certificates;
using CertificateAuthority;

namespace CAManagementTests.Unit;

public sealed class DistinguishedNameTests
{
    [Fact]
    public void Single_cn_matches_golden_der()
    {
        // SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String "Test" } } }
        byte[] expected =
        [
            0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B,
            0x06, 0x03, 0x55, 0x04, 0x03,
            0x0C, 0x04, 0x54, 0x65, 0x73, 0x74,
        ];

        var name = DistinguishedName.Builder().CommonName("Test").Build();

        Assert.Equal(expected, name.Encode());
    }

    [Fact]
    public void Country_is_encoded_as_printable_string()
    {
        var der = DistinguishedName.Builder().Country("CH").Build().Encode();

        // PrintableString tag 0x13 for the value "CH".
        Assert.Equal([0x13, 0x02, (byte)'C', (byte)'H'], der[^4..]);
    }

    [Fact]
    public void Encode_decode_round_trips_components_in_order()
    {
        var original = DistinguishedName.Builder()
            .Country("CH")
            .Organization("Hebel Consulting")
            .CommonName("Test CA")
            .Build();

        var decoded = DistinguishedName.Decode(original.Encode());

        Assert.Equal(original.Components, decoded.Components);
        Assert.Equal("C=CH, O=Hebel Consulting, CN=Test CA", decoded.ToString());
    }

    [Fact]
    public void Framework_parses_our_encoding()
    {
        var der = DistinguishedName.Builder()
            .Country("CH")
            .Organization("Hebel Consulting")
            .CommonName("Test CA")
            .Build()
            .Encode();

        var parsed = new X500DistinguishedName(der);
        var formatted = parsed.Decode(X500DistinguishedNameFlags.UseCommas);

        Assert.Contains("CN=Test CA", formatted);
        Assert.Contains("O=Hebel Consulting", formatted);
        Assert.Contains("C=CH", formatted);
    }

    [Fact]
    public void Framework_encoding_matches_ours_for_same_components()
    {
        var frameworkBuilder = new X500DistinguishedNameBuilder();
        frameworkBuilder.AddCountryOrRegion("CH");
        frameworkBuilder.AddOrganizationName("Hebel Consulting");
        frameworkBuilder.AddCommonName("Test CA");

        var ours = DistinguishedName.Builder()
            .Country("CH")
            .Organization("Hebel Consulting")
            .CommonName("Test CA")
            .Build()
            .Encode();

        // Order-insensitive comparison: both must decode to the same component set.
        var ourComponents = DistinguishedName.Decode(ours).Components;
        var frameworkComponents = DistinguishedName.Decode(frameworkBuilder.Build().RawData).Components;

        Assert.Equal(ourComponents.OrderBy(c => c.Oid), frameworkComponents.OrderBy(c => c.Oid));
    }

    [Fact]
    public void Rejects_invalid_country_and_empty_values()
    {
        Assert.Throws<ArgumentException>(() => DistinguishedName.Builder().Country("Switzerland"));
        Assert.Throws<ArgumentException>(() => DistinguishedName.Builder().CommonName(""));
        Assert.Throws<InvalidOperationException>(() => DistinguishedName.Builder().Build());
    }
}
