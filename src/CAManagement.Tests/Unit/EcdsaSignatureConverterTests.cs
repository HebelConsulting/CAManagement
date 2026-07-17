using System.Security.Cryptography;
using System.Text;
using CAManagement.Pkcs11.Signing;

namespace CAManagement.Tests.Unit;

public sealed class EcdsaSignatureConverterTests
{
    [Fact]
    public void Converts_minimal_values_to_golden_der()
    {
        // r=1, s=2 (32-byte fixed width) -> SEQUENCE { INTEGER 1, INTEGER 2 }
        var raw = new byte[64];
        raw[31] = 0x01;
        raw[63] = 0x02;

        Assert.Equal([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], EcdsaSignatureConverter.RawToDer(raw));
    }

    [Fact]
    public void High_bit_values_gain_a_leading_zero_octet()
    {
        // r with MSB set must be padded to stay a positive INTEGER.
        var raw = new byte[4];
        raw[0] = 0x80; // r = 0x8000
        raw[3] = 0x01; // s = 0x0001

        Assert.Equal([0x30, 0x08, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x01, 0x01], EcdsaSignatureConverter.RawToDer(raw));
    }

    [Fact]
    public void Framework_verifies_a_converted_p1363_signature()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var data = Encoding.UTF8.GetBytes("The quick brown fox");
        var p1363 = ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var der = EcdsaSignatureConverter.RawToDer(p1363);

        Assert.True(ecdsa.VerifyData(data, der, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public void Rejects_odd_length_input()
    {
        Assert.Throws<ArgumentException>(() => EcdsaSignatureConverter.RawToDer([0x01, 0x02, 0x03]));
    }
}
