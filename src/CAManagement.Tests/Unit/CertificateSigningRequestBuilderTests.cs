using System.Security.Cryptography;
using CAManagement.X509;

namespace CAManagement.Tests.Unit;

/// <summary>
/// The decoder is the oracle: it verifies a request's self-signature and refuses one that does not verify, so
/// a request this builder produces is checked here by exactly the rule it will meet at a CA. A builder tested
/// only against its own encoder would agree with itself.
/// </summary>
public sealed class CertificateSigningRequestBuilderTests
{
    [Fact]
    public void An_rsa_request_round_trips_through_the_decoder()
    {
        using var key = RSA.Create(2048);
        var parameters = key.ExportParameters(includePrivateParameters: false);

        var der = new CertificateSigningRequestBuilder
        {
            Subject = DistinguishedName.Builder().CommonName("Card Holder").Organization("Example").Build(),
            SubjectPublicKeyInfo = SubjectPublicKeyInfo.FromRsa(parameters.Modulus!, parameters.Exponent!),
        }.Sign(new RsaSoftwareSigner(key));

        var decoded = CertificateSigningRequest.Decode(der);   // verifies proof of possession

        Assert.Equal("CN=Card Holder, O=Example", decoded.Subject.ToString());
        Assert.Empty(decoded.RequestedExtensions);
    }

    [Fact]
    public void Requested_extensions_survive_the_round_trip()
    {
        using var key = RSA.Create(2048);
        var parameters = key.ExportParameters(includePrivateParameters: false);
        var spki = SubjectPublicKeyInfo.FromRsa(parameters.Modulus!, parameters.Exponent!);

        var der = new CertificateSigningRequestBuilder
        {
            Subject = DistinguishedName.Builder().CommonName("Card Holder").Build(),
            SubjectPublicKeyInfo = spki,
            RequestedExtensions = [CertificateExtensions.KeyUsage(KeyUsages.KeyEncipherment)],
        }.Sign(new RsaSoftwareSigner(key));

        var decoded = CertificateSigningRequest.Decode(der);

        var requested = Assert.Single(decoded.RequestedExtensions);
        Assert.Equal(Oids.KeyUsage, requested.Oid);
    }

    [Fact] // the empty case is the one that silently produces a structure nothing can parse
    public void A_request_without_extensions_still_carries_the_attributes_tag()
    {
        using var key = RSA.Create(2048);
        var parameters = key.ExportParameters(includePrivateParameters: false);

        var der = new CertificateSigningRequestBuilder
        {
            Subject = DistinguishedName.Builder().CommonName("No Extensions").Build(),
            SubjectPublicKeyInfo = SubjectPublicKeyInfo.FromRsa(parameters.Modulus!, parameters.Exponent!),
        }.Sign(new RsaSoftwareSigner(key));

        // The framework's own reader is a second, independent opinion on whether this is a valid PKCS#10.
        var framework = System.Security.Cryptography.X509Certificates.CertificateRequest.LoadSigningRequest(
            der, HashAlgorithmName.SHA256,
            System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions.Default,
            RSASignaturePadding.Pkcs1);

        Assert.Contains("No Extensions", framework.SubjectName.Name, StringComparison.Ordinal);
    }

    [Fact]
    public void A_tampered_request_no_longer_verifies()
    {
        using var key = RSA.Create(2048);
        var parameters = key.ExportParameters(includePrivateParameters: false);

        var der = new CertificateSigningRequestBuilder
        {
            Subject = DistinguishedName.Builder().CommonName("Card Holder").Build(),
            SubjectPublicKeyInfo = SubjectPublicKeyInfo.FromRsa(parameters.Modulus!, parameters.Exponent!),
        }.Sign(new RsaSoftwareSigner(key));

        der[^1] ^= 0xFF; // flip a bit in the signature

        Assert.Throws<CryptographicException>(() => CertificateSigningRequest.Decode(der));
    }
}
