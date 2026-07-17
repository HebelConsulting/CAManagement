using Pkcs11Interop;

namespace CAManagementTests.Unit;

public sealed class EllipticCurveTests
{
    [Fact]
    public void NistP256_ec_params_is_the_prime256v1_oid()
    {
        // DER OID 1.2.840.10045.3.1.7
        byte[] expected = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

        Assert.Equal(expected, EllipticCurve.NistP256.EcParams());
    }

    [Fact]
    public void NistP384_ec_params_is_the_secp384r1_oid()
    {
        // DER OID 1.3.132.0.34
        byte[] expected = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

        Assert.Equal(expected, EllipticCurve.NistP384.EcParams());
    }
}
