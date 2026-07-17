using System.Security.Cryptography;
using CertificateAuthority;

namespace CAManagementTests.Unit;

public sealed class SubjectPublicKeyInfoTests
{
    [Fact]
    public void Rsa_encoding_matches_framework_export()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);

        var spki = SubjectPublicKeyInfo.FromRsa(parameters.Modulus!, parameters.Exponent!);

        Assert.Equal(rsa.ExportSubjectPublicKeyInfo(), spki.Encode());
    }

    [Fact]
    public void Ec_encoding_matches_framework_export()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        var uncompressedPoint = (byte[])[0x04, .. parameters.Q.X!, .. parameters.Q.Y!];

        var spki = SubjectPublicKeyInfo.FromEc(Oids.Prime256V1, uncompressedPoint);

        Assert.Equal(ecdsa.ExportSubjectPublicKeyInfo(), spki.Encode());
    }

    [Fact]
    public void Key_identifier_is_sha1_of_the_key_bits()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);

        var spki = SubjectPublicKeyInfo.FromRsa(parameters.Modulus!, parameters.Exponent!);

        Assert.Equal(SHA1.HashData(spki.PublicKeyBytes), spki.ComputeKeyIdentifier());
        Assert.Equal(20, spki.ComputeKeyIdentifier().Length);
    }
}
