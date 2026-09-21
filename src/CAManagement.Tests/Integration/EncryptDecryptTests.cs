using System.Security.Cryptography;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Signing;

namespace CAManagement.Tests.Integration;

// Encrypt/decrypt against a real token (issue #1): added for envelope encryption, where the ONLY operation
// that genuinely needs the token is unwrapping a small data key with the token-resident private key. Bulk
// crypto never goes through PKCS#11, which is why there are deliberately no multi-part variants.
//
// The SHA-1 variants are the UNCONDITIONAL floor and the SHA-256 twins self-skip, not the other way round:
// SoftHSM 2.7.0 advertises CKM_RSA_PKCS_OAEP and then rejects any parameter hash but SHA-1 with
// CKR_ARGUMENTS_BAD — a restriction invisible to a mechanism-presence probe, found the hard way when the
// first SHA-256 init failed against a byte-perfect parameter block.
[Collection(SoftHsmCollection.Name)]
public sealed class EncryptDecryptTests(SoftHsmFixture fixture)
{
    [Fact]
    public void Round_trips_raw_rsa_encryption_on_the_token()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, privateKey) = session.GenerateRsaKeyPair($"enc-{Guid.NewGuid():N}");
        var data = RandomNumberGenerator.GetBytes(32);

        var ciphertext = session.Encrypt(CK_MECHANISM_TYPE.CKM_RSA_PKCS, data, publicKey);

        Assert.NotEqual(data, ciphertext[..data.Length]);
        Assert.Equal(data, session.Decrypt(CK_MECHANISM_TYPE.CKM_RSA_PKCS, ciphertext, privateKey));
    }

    [Fact]
    public void Round_trips_rsa_oaep_sha1_on_the_token()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, privateKey) = session.GenerateRsaKeyPair($"oaep-{Guid.NewGuid():N}");
        var data = RandomNumberGenerator.GetBytes(32);

        var ciphertext = session.EncryptRsaOaep(data, publicKey, CK_MECHANISM_TYPE.CKM_SHA_1);

        Assert.Equal(data, session.DecryptRsaOaep(ciphertext, privateKey, CK_MECHANISM_TYPE.CKM_SHA_1));
    }

    [Fact]
    public void Round_trips_rsa_oaep_sha256_where_the_token_allows_it()
    {
        if (!fixture.SupportsRsaOaepSha256()) { return; } // SoftHSM 2.7.0 is SHA-1-only for OAEP

        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, privateKey) = session.GenerateRsaKeyPair($"oaep256-{Guid.NewGuid():N}");
        var data = RandomNumberGenerator.GetBytes(32);

        var ciphertext = session.EncryptRsaOaep(data, publicKey);

        Assert.Equal(data, session.DecryptRsaOaep(ciphertext, privateKey));
    }

    // THE test this feature exists for, and the only kind that can catch an OAEP parameter-marshalling
    // mistake: the consumer wraps a 32-byte data key IN SOFTWARE (.NET RSA) against the token key's exported
    // SPKI, and the token must unwrap it. An on-token round trip alone proves nothing about interop — a
    // wrong CK_RSA_PKCS_OAEP_PARAMS image would encrypt and decrypt consistently with itself and fail only
    // against an independent implementation.
    [Fact]
    public void A_data_key_wrapped_in_software_is_unwrapped_by_the_token()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, privateKey) = session.GenerateRsaKeyPair($"wrap-{Guid.NewGuid():N}");
        var spki = Pkcs11PublicKeyReader.Read(session, publicKey).Encode();

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(spki, out _);
        var dataKey = RandomNumberGenerator.GetBytes(32);
        var wrapped = rsa.Encrypt(dataKey, RSAEncryptionPadding.OaepSHA1);

        Assert.Equal(dataKey, session.DecryptRsaOaep(wrapped, privateKey, CK_MECHANISM_TYPE.CKM_SHA_1));
    }

    [Fact]
    public void A_data_key_wrapped_in_software_with_sha256_is_unwrapped_where_the_token_allows_it()
    {
        if (!fixture.SupportsRsaOaepSha256()) { return; }

        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (publicKey, privateKey) = session.GenerateRsaKeyPair($"wrap256-{Guid.NewGuid():N}");
        var spki = Pkcs11PublicKeyReader.Read(session, publicKey).Encode();

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(spki, out _);
        var dataKey = RandomNumberGenerator.GetBytes(32);
        var wrapped = rsa.Encrypt(dataKey, RSAEncryptionPadding.OaepSHA256);

        Assert.Equal(dataKey, session.DecryptRsaOaep(wrapped, privateKey));
    }

    [Fact]
    public void Decrypting_garbage_reports_a_pkcs11_error_rather_than_returning_bytes()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var (_, privateKey) = session.GenerateRsaKeyPair($"bad-{Guid.NewGuid():N}");

        Assert.Throws<Pkcs11Exception>(() =>
            session.DecryptRsaOaep(RandomNumberGenerator.GetBytes(256), privateKey, CK_MECHANISM_TYPE.CKM_SHA_1));
    }
}
