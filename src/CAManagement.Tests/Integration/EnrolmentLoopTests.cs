using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Signing;
using CAManagement.X509;

namespace CAManagement.Tests.Integration;

/// <summary>
/// The enrolment loop a card goes through, against a real token: a key that never leaves it produces a
/// request, the CA signs it, and the issued certificate goes back onto the token beside its key.
///
/// Until <c>csr</c> existed the middle step had no home here — <c>issue</c> could sign a request and nothing
/// could produce one — so the only way to enrol a token-resident key was the card vendor's own tool. This
/// asserts the loop closes without one.
/// </summary>
[Collection(SoftHsmCollection.Name)]
public sealed class EnrolmentLoopTests(SoftHsmFixture fixture)
{
    [Fact]
    public void A_token_key_is_enrolled_end_to_end_without_vendor_tooling()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var login = session.Login(SoftHsmFixture.UserPin);

        var caLabel = $"ca-{Guid.NewGuid():N}"[..20];
        var holderLabel = $"holder-{Guid.NewGuid():N}"[..20];

        // Two keys on the token: the CA's, and the "card holder's" whose private half never leaves.
        session.GenerateRsaKeyPair(caLabel);
        session.GenerateRsaKeyPair(holderLabel);

        var (caSigner, caSpki) = LoadKey(session, caLabel);
        var (holderSigner, holderSpki) = LoadKey(session, holderLabel);

        var caSubject = DistinguishedName.Builder().CommonName("Enrolment Test CA").Build();
        var caCertificate = new CertificateBuilder
        {
            Subject = caSubject,
            SubjectPublicKeyInfo = caSpki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
            Extensions = [CertificateExtensions.BasicConstraints(isCa: true, pathLengthConstraint: 0)],
        }.SignSelfSigned(caSigner);

        // 1. the request, signed BY THE TOKEN KEY it is for
        var csrDer = new CertificateSigningRequestBuilder
        {
            Subject = DistinguishedName.Builder().CommonName("Card Holder").Build(),
            SubjectPublicKeyInfo = holderSpki,
        }.Sign(holderSigner);

        // 2. the CA reads it — Decode verifies the proof of possession, so this step is also the assertion
        //    that the token really signed it
        var request = CertificateSigningRequest.Decode(csrDer);
        Assert.Equal("CN=Card Holder", request.Subject.ToString());

        var issued = new CertificateBuilder
        {
            Subject = request.Subject,
            SubjectPublicKeyInfo = request.SubjectPublicKeyInfo,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(1),
        }.Sign(caSubject, caSigner);

        // 3. back onto the token, beside the key
        var certificateSubject = System.Security.Cryptography.X509Certificates.X509CertificateLoader
            .LoadCertificate(issued).SubjectName.RawData;
        session.ImportX509Certificate(holderLabel, issued, certificateSubject);

        var stored = session.FindObjects(CK_OBJECT_CLASS.CKO_CERTIFICATE, holderLabel);
        Assert.Single(stored);

        // The issued certificate carries the TOKEN's public key — not some other key that happened to be
        // lying around. That is the property the whole loop exists to preserve.
        Assert.Equal(holderSpki.Encode(), request.SubjectPublicKeyInfo.Encode());
    }

    private static (Pkcs11CertificateSigner Signer, SubjectPublicKeyInfo Spki) LoadKey(Pkcs11Session session, string label)
    {
        var privateKey = Assert.Single(session.FindObjects(CK_OBJECT_CLASS.CKO_PRIVATE_KEY, label));
        var publicKey = Assert.Single(session.FindObjects(CK_OBJECT_CLASS.CKO_PUBLIC_KEY, label));
        return (Pkcs11CertificateSigner.ForKey(session, privateKey), Pkcs11PublicKeyReader.Read(session, publicKey));
    }
}
