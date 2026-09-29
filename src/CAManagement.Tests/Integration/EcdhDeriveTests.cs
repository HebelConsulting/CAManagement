using System.Security.Cryptography;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;

namespace CAManagement.Tests.Integration;

// ECDH key agreement against a real token: the operation an elliptic-curve CMS recipient needs, where the
// content-encryption key is AGREED rather than wrapped.
//
// WHY IT IS WORTH AN INTEGRATION TEST RATHER THAN A UNIT ONE. Nothing about C_DeriveKey can be checked in
// managed memory: the derived value is produced INSIDE the token, comes back as a key OBJECT rather than a
// buffer, and the whole risk sits in the marshalling of CK_ECDH1_DERIVE_PARAMS — three CK_ULONG-adjacent
// fields whose width differs between Unix (8 bytes) and Windows (4, packed to 1). A mock would agree with
// whatever the code did.
//
// The assertion is therefore always the same: the token's answer must equal the secret computed
// INDEPENDENTLY in managed code from the other side of the exchange. A marshalling mistake cannot survive
// that, and cannot hide behind a test that only checks the call returned something.
[Collection(SoftHsmCollection.Name)]
public sealed class EcdhDeriveTests(SoftHsmFixture fixture)
{
    [Fact]
    public void Derives_the_same_secret_the_peer_computes()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (tokenPublic, tokenPrivate) = session.GenerateEcKeyPair(
            $"ecdh-{Guid.NewGuid():N}", usage: Pkcs11KeyPairUsage.KeyAgreement);

        // The peer is ordinary managed code — which is the point: it is an independent implementation, so
        // agreement means the token did the real thing rather than that both sides share a bug.
        using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        var tokenPoint = UncompressedPoint(session.GetAttributeValue(tokenPublic, CK_ATTRIBUTE_TYPE.CKA_EC_POINT));
        var peerPoint = UncompressedPoint(peer);

        var fromToken = session.DeriveEcdhSecret(peerPoint, tokenPrivate);
        var fromPeer = peer.DeriveRawSecretAgreement(ImportPoint(tokenPoint));

        // RAW agreement on both sides: DeriveRawSecretAgreement is the unhashed Z, which is what CKD_NULL
        // returns. Comparing against DeriveKeyMaterial would compare Z with a hash of Z and fail for a
        // reason that has nothing to do with the token.
        Assert.Equal(fromPeer, fromToken);
        Assert.Equal(32, fromToken.Length);
    }

    [Fact]
    public void A_second_derivation_with_the_same_inputs_is_stable()
    {
        // Deriving twice must agree, which sounds trivial and is the cheapest check that the derived key
        // object is being read and DESTROYED correctly: a leaked or reused handle shows up here first.
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (_, tokenPrivate) = session.GenerateEcKeyPair(
            $"ecdh-stable-{Guid.NewGuid():N}", usage: Pkcs11KeyPairUsage.KeyAgreement);
        using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var peerPoint = UncompressedPoint(peer);

        Assert.Equal(
            session.DeriveEcdhSecret(peerPoint, tokenPrivate),
            session.DeriveEcdhSecret(peerPoint, tokenPrivate));
    }

    [Fact]
    public void An_empty_peer_point_is_refused_before_the_token_is_touched()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (_, tokenPrivate) = session.GenerateEcKeyPair(
            $"ecdh-empty-{Guid.NewGuid():N}", usage: Pkcs11KeyPairUsage.KeyAgreement);

        // Refused in managed code rather than passed through: an empty pPublicData is exactly the shape that
        // makes a token segfault rather than return CKR_ARGUMENTS_BAD, and a dead process reports nothing.
        Assert.Throws<ArgumentException>(() => session.DeriveEcdhSecret([], tokenPrivate));
    }

    // --- helpers ----------------------------------------------------------------------------------------

    /// <summary>
    /// The uncompressed <c>04||X||Y</c> point from CKA_EC_POINT, which the token returns DER-wrapped.
    /// </summary>
    /// <remarks>
    /// PKCS#11 says CKA_EC_POINT is an ASN.1 OCTET STRING containing the point, so the bytes come back with a
    /// <c>04 &lt;len&gt;</c> header before the <c>04</c> that means "uncompressed" — two different 0x04s in a
    /// row, which is the trap. Stripping by a fixed offset would work for P-256 and break on P-384, where the
    /// length needs two bytes.
    /// </remarks>
    private static byte[] UncompressedPoint(byte[] ckaEcPoint)
    {
        if (ckaEcPoint.Length > 2 && ckaEcPoint[0] == 0x04 && ckaEcPoint[1] == ckaEcPoint.Length - 2)
        {
            return ckaEcPoint[2..];
        }

        // Long form: 0x04, 0x81, length — used once a point exceeds 127 bytes (P-521).
        if (ckaEcPoint.Length > 3 && ckaEcPoint[0] == 0x04 && ckaEcPoint[1] == 0x81)
        {
            return ckaEcPoint[3..];
        }

        return ckaEcPoint;
    }

    private static byte[] UncompressedPoint(ECDiffieHellman key)
    {
        var parameters = key.ExportParameters(false);
        return [0x04, .. parameters.Q.X!, .. parameters.Q.Y!];
    }

    private static ECDiffieHellmanPublicKey ImportPoint(byte[] uncompressed)
    {
        var half = (uncompressed.Length - 1) / 2;
        using var imported = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = uncompressed[1..(1 + half)], Y = uncompressed[(1 + half)..] },
        });
        return imported.PublicKey;
    }
}
