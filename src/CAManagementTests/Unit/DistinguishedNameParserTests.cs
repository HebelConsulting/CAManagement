using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using CertificateAuthority;

namespace CAManagementTests.Unit;

public sealed class DistinguishedNameParserTests
{
    [Fact]
    public void Parses_openssl_slash_form_in_order()
    {
        var name = DistinguishedName.Parse(
            "/CN=www.test.org/O=Hebel Consulting GmbH/OU=IT Department/DC=www/DC=test/DC=org");

        Assert.Equal(
            [
                (Oids.CommonName, "www.test.org"),
                (Oids.Organization, "Hebel Consulting GmbH"),
                (Oids.OrganizationalUnit, "IT Department"),
                (Oids.DomainComponent, "www"),
                (Oids.DomainComponent, "test"),
                (Oids.DomainComponent, "org"),
            ],
            name.Components.Select(c => (c.Oid, c.Value)));
        Assert.All(name.Components, c => Assert.Null(c.StringType));
    }

    [Fact]
    public void Parses_string_type_annotations_including_hyphenated_spelling()
    {
        var name = DistinguishedName.Parse(
            "/CN=[PrintableString]www.test.org/O=[UTF8-String]Hebel Consulting GmbH/OU=IT Department");

        Assert.Equal(UniversalTagNumber.PrintableString, name.Components[0].StringType);
        Assert.Equal(UniversalTagNumber.UTF8String, name.Components[1].StringType);
        Assert.Null(name.Components[2].StringType);

        // The annotation must reach the encoded bytes: CN as PrintableString (tag 0x13).
        var der = name.Encode();
        var cn = new AsnReader(der, AsnEncodingRules.DER).ReadSequence().ReadSetOf().ReadSequence();
        cn.ReadObjectIdentifier();
        Assert.Equal((int)UniversalTagNumber.PrintableString, cn.PeekTag().TagValue);
    }

    [Fact]
    public void Parses_comma_form_with_annotations_too()
    {
        var name = DistinguishedName.Parse("C=CH, O=Hebel Consulting, CN=[PrintableString]Test CA");

        Assert.Equal(3, name.Components.Count);
        Assert.Equal(UniversalTagNumber.PrintableString, name.Components[2].StringType);
    }

    [Fact]
    public void Slash_form_unescapes_escaped_slashes()
    {
        var name = DistinguishedName.Parse(@"/CN=path\/with\/slashes/O=Example");

        Assert.Equal("path/with/slashes", name.Components[0].Value);
        Assert.Equal("Example", name.Components[1].Value);
    }

    [Fact]
    public void Comma_form_unescapes_escaped_commas()
    {
        var name = DistinguishedName.Parse(@"O=ACME\, Inc., CN=Escaped");

        Assert.Equal(2, name.Components.Count);
        Assert.Equal("ACME, Inc.", name.Components[0].Value);
        Assert.Equal("Escaped", name.Components[1].Value);
    }

    [Fact]
    public void Backslash_escapes_itself_in_both_forms()
    {
        Assert.Equal(@"a\b", DistinguishedName.Parse(@"CN=a\\b").Components[0].Value);
        Assert.Equal(@"a\b", DistinguishedName.Parse(@"/CN=a\\b").Components[0].Value);
    }

    [Fact]
    public void Dotted_oid_keys_are_accepted()
    {
        var name = DistinguishedName.Parse("/2.5.4.3=Direct OID");

        Assert.Equal(Oids.CommonName, name.Components[0].Oid);
    }

    [Theory]
    [InlineData("/CN=")]                      // empty value
    [InlineData("/UNKNOWN=x")]                // unknown key
    [InlineData("/CN=[NoSuchString]value")]   // unknown annotation
    [InlineData("no separator")]              // not key=value
    [InlineData("")]                          // empty input
    public void Rejects_invalid_input(string text)
    {
        Assert.ThrowsAny<Exception>(() => DistinguishedName.Parse(text));
    }

    [Fact]
    public void Decode_then_encode_is_byte_faithful_for_foreign_encodings()
    {
        // The framework's legacy DN encoder uses PrintableString for ASCII values —
        // different from our UTF8String default, so fidelity requires remembering
        // the original string types.
        var foreign = new X500DistinguishedName("CN=Fidelity Test, O=Example Org").RawData;

        var decoded = DistinguishedName.Decode(foreign);

        Assert.Equal(foreign, decoded.Encode());
    }
}
