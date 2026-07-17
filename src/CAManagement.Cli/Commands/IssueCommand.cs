using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using CAManagement.Cli.Infrastructure;
using CAManagement.X509;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Issues a certificate from a PKCS#10 CSR, signed by the token-resident CA key.</summary>
public sealed class IssueCommand(HsmCa hsm) : Command<IssueCommand.Settings>
{
    public sealed class Settings : CommandSettings
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

        [CommandOption("--pin <PIN>")]
        public string? Pin { get; init; }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var _ = hsm;
        var session = hsm.OpenLoggedInSession(settings.Pin);
        var (signer, caSpki) = hsm.LoadCaKey(session, settings.CaLabel);

        var issuer = X509Names.SubjectOf(File.ReadAllBytes(settings.CaCert));

        var csr = CertificateSigningRequest.Decode(ReadDer(settings.Csr)); // verifies proof of possession

        var certificateDer = new CertificateBuilder
        {
            Subject = csr.Subject,
            SubjectPublicKeyInfo = csr.SubjectPublicKeyInfo,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddDays(settings.Days),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: false),
                CertificateExtensions.KeyUsage(KeyUsages.DigitalSignature),
                CertificateExtensions.SubjectKeyIdentifier(csr.SubjectPublicKeyInfo.ComputeKeyIdentifier()),
                CertificateExtensions.AuthorityKeyIdentifier(caSpki.ComputeKeyIdentifier()),
                // CA policy: subject alternative names are the only extension request honored.
                .. csr.RequestedExtensions.Where(e => e.Oid == Oids.SubjectAlternativeName),
            ],
        }.Sign(issuer, signer);

        File.WriteAllText(settings.Out, Pem.Encode("CERTIFICATE", certificateDer));

        using var issued = X509CertificateLoader.LoadCertificate(certificateDer);
        AnsiConsole.MarkupLine($"[green]Issued[/] [blue]{Markup.Escape(issued.Subject)}[/], " +
            $"serial [yellow]{issued.SerialNumber}[/], valid {settings.Days} days, written to [blue]{settings.Out}[/].");

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
