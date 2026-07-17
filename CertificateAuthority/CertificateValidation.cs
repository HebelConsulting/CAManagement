using System.Security.Cryptography.X509Certificates;

namespace CertificateAuthority;

public sealed record ChainValidationResult(bool IsValid, IReadOnlyList<string> Errors, IReadOnlyList<byte[]> ChainDer);

/// <summary>
/// Chain validation for CA-issued certificates. Deliberately a thin wrapper over
/// <see cref="X509Chain"/> with custom root trust — path validation is
/// security-critical framework territory, not something this library re-authors
/// (same reasoning as SPEC D1 for TLV). Revocation is not checked here: the
/// framework cannot consume our CRLs offline; check them explicitly if needed.
/// </summary>
public static class CertificateValidation
{
    public static ChainValidationResult Validate(
        byte[] certificateDer,
        IReadOnlyList<byte[]> trustedRootsDer,
        IReadOnlyList<byte[]>? intermediatesDer = null,
        DateTimeOffset? validationTime = null)
    {
        var loaded = new List<X509Certificate2>();
        try
        {
            using var certificate = X509CertificateLoader.LoadCertificate(certificateDer);
            using var chain = new X509Chain();

            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            if (validationTime is { } time)
            {
                chain.ChainPolicy.VerificationTime = time.UtcDateTime;
            }

            foreach (var rootDer in trustedRootsDer)
            {
                var root = X509CertificateLoader.LoadCertificate(rootDer);
                loaded.Add(root);
                chain.ChainPolicy.CustomTrustStore.Add(root);
            }

            foreach (var intermediateDer in intermediatesDer ?? [])
            {
                var intermediate = X509CertificateLoader.LoadCertificate(intermediateDer);
                loaded.Add(intermediate);
                chain.ChainPolicy.ExtraStore.Add(intermediate);
            }

            var isValid = chain.Build(certificate);

            var errors = chain.ChainStatus
                .Select(status => $"{status.Status}: {status.StatusInformation.Trim()}")
                .ToArray();
            var chainDer = chain.ChainElements
                .Select(element => element.Certificate.RawData)
                .ToArray();

            return new ChainValidationResult(isValid, errors, chainDer);
        }
        finally
        {
            foreach (var certificate in loaded)
            {
                certificate.Dispose();
            }
        }
    }
}
