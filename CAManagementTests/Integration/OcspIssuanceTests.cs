using System.Formats.Asn1;
using System.Security.Cryptography;
using CertificateAuthority;
using CertificateAuthority.Ocsp;
using Pkcs11Interop;
using Pkcs11Signing;

namespace CAManagementTests.Integration;

[Collection(SoftHsmCollection.Name)]
public sealed class OcspIssuanceTests(SoftHsmFixture fixture)
{
    [Fact]
    public void Hsm_backed_ca_signs_an_ocsp_response_that_verifies()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var label = $"ocsp-ca-{Guid.NewGuid():N}";
        var (publicKey, privateKey) = session.GenerateEcKeyPair(label);
        var caSpki = Pkcs11PublicKeyReader.Read(session, publicKey);
        var caSigner = new Pkcs11CertificateSigner(session, privateKey, SignatureAlgorithm.EcdsaWithSha256);
        var caName = DistinguishedName.Builder().Country("CH").CommonName($"OCSP HSM CA {label}").Build();

        var certId = OcspCertId.Create(HashAlgorithmName.SHA1, caName.Encode(), caSpki, [0x1A, 0x2B, 0x3C]);

        var responseDer = new OcspResponseBuilder
        {
            ResponderPublicKey = caSpki,
            ProducedAt = DateTimeOffset.UtcNow,
            Responses =
            [
                OcspSingleResponse.Revoked(certId, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(-1),
                    RevocationReason.Superseded, DateTimeOffset.UtcNow.AddDays(1)),
            ],
        }.Sign(caSigner);

        // Unwrap OCSPResponse -> BasicOCSPResponse and verify the HSM signature.
        var response = new AsnReader(responseDer, AsnEncodingRules.DER).ReadSequence();
        Assert.Equal(OcspResponseStatus.Successful, response.ReadEnumeratedValue<OcspResponseStatus>());
        var responseBytes = response.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
        Assert.Equal(Oids.OcspBasicResponse, responseBytes.ReadObjectIdentifier());
        var basic = new AsnReader(responseBytes.ReadOctetString(), AsnEncodingRules.DER).ReadSequence();

        var tbsResponseData = basic.PeekEncodedValue().ToArray();
        basic.ReadSequence();
        basic.ReadSequence(); // signatureAlgorithm
        var signature = basic.ReadBitString(out _);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(caSpki.Encode(), out _);
        Assert.True(ecdsa.VerifyData(tbsResponseData, signature, HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence), "HSM OCSP signature must verify against the CA public key");
    }
}
