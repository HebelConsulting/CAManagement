using CAManagement.X509;

namespace CAManagement.Tests.Unit;

public sealed class CertificateExtensionTests
{
    [Fact]
    public void Basic_constraints_for_a_ca_matches_golden_der()
    {
        var extension = CertificateExtensions.BasicConstraints(isCa: true);

        Assert.Equal(Oids.BasicConstraints, extension.Oid);
        Assert.True(extension.Critical);
        Assert.Equal([0x30, 0x03, 0x01, 0x01, 0xFF], extension.Value); // SEQUENCE { TRUE }
    }

    [Fact]
    public void Basic_constraints_with_path_length_encodes_the_integer()
    {
        var extension = CertificateExtensions.BasicConstraints(isCa: true, pathLengthConstraint: 0);

        Assert.Equal([0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00], extension.Value);
    }

    [Fact]
    public void Basic_constraints_for_end_entity_is_an_empty_sequence()
    {
        // cA DEFAULT FALSE must be omitted in DER.
        Assert.Equal([0x30, 0x00], CertificateExtensions.BasicConstraints(isCa: false).Value);
    }

    [Fact]
    public void Key_usage_for_a_ca_matches_golden_der()
    {
        var extension = CertificateExtensions.KeyUsage(KeyUsages.KeyCertSign | KeyUsages.CrlSign);

        // BIT STRING, 1 unused bit, 0b0000_0110 -> keyCertSign(5) + cRLSign(6).
        Assert.Equal([0x03, 0x02, 0x01, 0x06], extension.Value);
        Assert.True(extension.Critical);
    }

    [Fact]
    public void Subject_key_identifier_wraps_the_identifier_in_an_octet_string()
    {
        var keyIdentifier = Enumerable.Repeat((byte)0xAB, 20).ToArray();

        var extension = CertificateExtensions.SubjectKeyIdentifier(keyIdentifier);

        Assert.False(extension.Critical);
        Assert.Equal([(byte)0x04, (byte)0x14, .. keyIdentifier], extension.Value);
    }

    [Fact]
    public void Authority_key_identifier_uses_the_context_0_form()
    {
        var keyIdentifier = Enumerable.Repeat((byte)0xCD, 20).ToArray();

        var extension = CertificateExtensions.AuthorityKeyIdentifier(keyIdentifier);

        // SEQUENCE { [0] IMPLICIT OCTET STRING (20 bytes) }
        Assert.Equal([(byte)0x30, (byte)0x16, (byte)0x80, (byte)0x14, .. keyIdentifier], extension.Value);
    }

    [Fact]
    public void Extended_key_usage_lists_the_purpose_oids()
    {
        var extension = CertificateExtensions.ExtendedKeyUsage(Oids.ServerAuthentication, Oids.ClientAuthentication);

        Assert.Equal(
            [
                0x30, 0x14,
                0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
                0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
            ],
            extension.Value);
    }
}
