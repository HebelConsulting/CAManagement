using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using CAManagement.Cli.Infrastructure;
using CAManagement.X509;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Issues a certificate from a PKCS#10 CSR, signed by the token-resident CA key.</summary>
public sealed class IssueCommand : Command<IssueCommand.Settings>
{
    public sealed class Settings : HsmLoginSettings
    {
        [CommandOption("--ca-label <LABEL>")]
        [Description("Token label of the CA key pair.")]
        public required string CaLabel { get; init; }

        [CommandOption("--ca-cert <FILE>")]
        [Description("The CA certificate (PEM or DER); its subject becomes the issuer.")]
        public required string CaCert { get; init; }

        [CommandOption("--csr <FILE>")]
        [Description("PKCS#10 request (PEM or DER); its self-signature is verified.")]
        public required string Csr { get; init; }

        [CommandOption("--days <DAYS>")]
        [DefaultValue(365)]
        public int Days { get; init; } = 365;

        [CommandOption("--out <FILE>")]
        [DefaultValue("leaf.crt")]
        public string Out { get; init; } = "leaf.crt";

        [CommandOption("--profile <PROFILE>")]
        [Description("What the certificate is FOR: 'signing' (default) or 'key-management' (a decryption "
            + "certificate — keyAgreement for EC, keyEncipherment for RSA, plus emailProtection).")]
        [DefaultValue("signing")]
        public string Profile { get; init; } = "signing";
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var hsm = new HsmCa();
        var session = hsm.OpenLoggedInSession(settings, settings.Pin);
        var (signer, caSpki) = hsm.LoadCaKey(session, settings.CaLabel);

        var issuer = X509Names.SubjectOf(File.ReadAllBytes(settings.CaCert));

        var csr = CertificateSigningRequest.Decode(ReadDer(settings.Csr)); // verifies proof of possession

        // WHAT THE CERTIFICATE IS FOR decides the keyUsage, and the KEY decides which bit expresses it
        // (#18). This used to be a hard-coded `digitalSignature`, which is the one bit that does not apply to
        // a decryption certificate — so a certificate issued for a PIV Key Management slot declared a usage
        // it could never honour, worked anyway against consumers that do not check, and was refused by the
        // ones that do.
        var purpose = CertificatePurpose.For(
            CertificatePurpose.Parse(settings.Profile), csr.SubjectPublicKeyInfo.AlgorithmOid);

        var certificateDer = new CertificateBuilder
        {
            Subject = csr.Subject,
            SubjectPublicKeyInfo = csr.SubjectPublicKeyInfo,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddDays(settings.Days),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: false),
                CertificateExtensions.KeyUsage(purpose.KeyUsage),
                .. purpose.ExtendedKeyUsages.Count > 0
                    ? new[] { CertificateExtensions.ExtendedKeyUsage([.. purpose.ExtendedKeyUsages]) }
                    : [],
                CertificateExtensions.SubjectKeyIdentifier(csr.SubjectPublicKeyInfo.ComputeKeyIdentifier()),
                CertificateExtensions.AuthorityKeyIdentifier(caSpki.ComputeKeyIdentifier()),
                // CA policy: subject alternative names are the only extension request honored.
                .. csr.RequestedExtensions.Where(e => e.Oid == Oids.SubjectAlternativeName),
            ],
        }.Sign(issuer, signer);

        File.WriteAllText(settings.Out, Pem.Encode("CERTIFICATE", certificateDer));

        using var issued = X509CertificateLoader.LoadCertificate(certificateDer);
        // The USAGE is named in the output, because it is the thing that silently differed: a certificate
        // whose keyUsage is wrong looks identical to a correct one everywhere except where it is checked.
        AnsiConsole.MarkupLine($"[green]Issued[/] [blue]{Markup.Escape(issued.Subject)}[/], " +
            $"serial [yellow]{issued.SerialNumber}[/], valid {settings.Days} days, " +
            $"keyUsage [yellow]{purpose.KeyUsage}[/], written to [blue]{settings.Out}[/].");

        return 0;
    }

    internal static byte[] ReadDer(string path)
    {
        var bytes = File.ReadAllBytes(path);

        return bytes.Length > 10 && bytes.AsSpan(0, 5).SequenceEqual("-----"u8)
            ? Pem.TryDecodeFirst(System.Text.Encoding.ASCII.GetString(bytes))?.Der
              ?? throw new FormatException($"'{path}' looks like PEM but contains no PEM block.")
            : bytes;
    }
}
