using CAManagement.X509;

namespace CAManagement.Tests.Unit;

public sealed class AlgorithmIdentifierTests
{
    [Fact]
    public void Sha256WithRsa_encodes_with_explicit_null_parameters()
    {
        // SEQUENCE { OID 1.2.840.113549.1.1.11, NULL } — RFC 5280 golden bytes.
        byte[] expected = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00];

        Assert.Equal(expected, AlgorithmIdentifier.For(SignatureAlgorithm.Sha256WithRsa).Encode());
    }

    [Fact]
    public void EcdsaWithSha256_encodes_without_parameters()
    {
        // SEQUENCE { OID 1.2.840.10045.4.3.2 } — parameters absent per RFC 5758 §3.2.
        byte[] expected = [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

        Assert.Equal(expected, AlgorithmIdentifier.For(SignatureAlgorithm.EcdsaWithSha256).Encode());
    }

    [Theory]
    [InlineData(SignatureAlgorithm.Sha384WithRsa, Oids.Sha384WithRsaEncryption, true)]
    [InlineData(SignatureAlgorithm.Sha512WithRsa, Oids.Sha512WithRsaEncryption, true)]
    [InlineData(SignatureAlgorithm.EcdsaWithSha384, Oids.EcdsaWithSha384, false)]
    [InlineData(SignatureAlgorithm.EcdsaWithSha512, Oids.EcdsaWithSha512, false)]
    public void Maps_algorithm_to_oid_and_parameter_form(SignatureAlgorithm algorithm, string expectedOid, bool expectNullParameters)
    {
        var identifier = AlgorithmIdentifier.For(algorithm);

        Assert.Equal(expectedOid, identifier.Oid);
        Assert.Equal(expectNullParameters, identifier.HasNullParameters);
    }
}
