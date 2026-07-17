using System.Formats.Asn1;
using System.Security.Cryptography;
using CAManagement.X509;
using CAManagement.X509.Ocsp;

namespace CAManagement.Cli.Infrastructure;

/// <summary>
/// OCSP responder policy over the console's CA state (the CAManagement.X509
/// library stays policy-free per SPEC D5): serials recorded in ca-state.json are
/// revoked, other serials of our CA are good (issuance is not tracked), and
/// CertIDs for foreign issuers are unknown. Nonces are echoed; the CA
/// certificate is embedded so clients can verify the signature.
/// </summary>
public sealed class OcspResponderService(
    byte[] issuerNameDer,
    SubjectPublicKeyInfo caPublicKey,
    ICertificateSigner signer,
    byte[] caCertificateDer,
    CaStateFile state,
    TimeSpan validity)
{
    public byte[] Respond(byte[] requestDer)
    {
        OcspRequest request;
        try
        {
            request = OcspRequest.Decode(requestDer);
        }
        catch (Exception exception) when (exception is AsnContentException or CryptographicException or FormatException)
        {
            return OcspResponseBuilder.CreateError(OcspResponseStatus.MalformedRequest);
        }

        var now = DateTimeOffset.UtcNow;

        return new OcspResponseBuilder
        {
            ResponderPublicKey = caPublicKey,
            ProducedAt = now,
            Responses = request.Requests.Select(certId => BuildSingleResponse(certId, now)).ToArray(),
            Nonce = request.Nonce,
            Certificates = [caCertificateDer],
        }.Sign(signer);
    }

    private OcspSingleResponse BuildSingleResponse(OcspCertId certId, DateTimeOffset now)
    {
        bool aboutOurCa;
        try
        {
            aboutOurCa = certId.MatchesIssuer(issuerNameDer, caPublicKey);
        }
        catch (NotSupportedException)
        {
            aboutOurCa = false; // hash algorithm we cannot compute -> we cannot vouch
        }

        if (!aboutOurCa)
        {
            return OcspSingleResponse.Unknown(certId, now);
        }

        var serialHex = Convert.ToHexString(certId.SerialNumber);
        var entry = state.Revoked.FirstOrDefault(r => NormalizeSerialHex(r.SerialHex) == serialHex);
        var nextUpdate = now + validity;

        return entry is null
            ? OcspSingleResponse.Good(certId, now, nextUpdate)
            : OcspSingleResponse.Revoked(certId, now, entry.RevokedAtUtc, entry.Reason, nextUpdate);
    }

    private static string NormalizeSerialHex(string hex)
    {
        var bytes = Convert.FromHexString(hex.Length % 2 == 0 ? hex : $"0{hex}").AsSpan().TrimStart((byte)0);

        return bytes.IsEmpty ? "00" : Convert.ToHexString(bytes);
    }
}
