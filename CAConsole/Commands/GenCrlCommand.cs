using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using CAConsole.Infrastructure;
using CertificateAuthority;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAConsole.Commands;

/// <summary>Signs a CRL from the CA state file with the token-resident CA key.</summary>
public sealed class GenCrlCommand(HsmCa hsm) : Command<GenCrlCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [CommandOption("--ca-label <LABEL>")]
        [Description("Token label of the CA key pair.")]
        public required string CaLabel { get; init; }

        [CommandOption("--ca-cert <FILE>")]
        [Description("The CA certificate (PEM or DER); its subject becomes the CRL issuer.")]
        public required string CaCert { get; init; }

        [CommandOption("--state <FILE>")]
        [DefaultValue("ca-state.json")]
        public string State { get; init; } = "ca-state.json";

        [CommandOption("--days <DAYS>")]
        [Description("Days until nextUpdate.")]
        [DefaultValue(7)]
        public int Days { get; init; } = 7;

        [CommandOption("--out <FILE>")]
        [DefaultValue("ca.crl")]
        public string Out { get; init; } = "ca.crl";

        [CommandOption("--pin <PIN>")]
        public string? Pin { get; init; }
    }

    public override int Execute(CommandContext context, Settings settings)
    {
        using var _ = hsm;
        var session = hsm.OpenLoggedInSession(settings.Pin);
        var (signer, caSpki) = hsm.LoadCaKey(session, settings.CaLabel);

        using var caCertificate = X509CertificateLoader.LoadCertificate(IssueCommand.ReadDer(settings.CaCert));
        var issuer = DistinguishedName.Decode(caCertificate.SubjectName.RawData);

        var state = CaStateFile.Load(settings.State);
        state.CrlNumber++;

        var crlDer = new CrlBuilder
        {
            Issuer = issuer,
            ThisUpdate = DateTimeOffset.UtcNow,
            NextUpdate = DateTimeOffset.UtcNow.AddDays(settings.Days),
            CrlNumber = state.CrlNumber,
            AuthorityKeyIdentifier = caSpki.ComputeKeyIdentifier(),
            RevokedCertificates = state.Revoked
                .Select(r => new RevokedCertificate(Convert.FromHexString(r.SerialHex), r.RevokedAtUtc, r.Reason))
                .ToArray(),
        }.Sign(signer);

        File.WriteAllText(settings.Out, Pem.Encode("X509 CRL", crlDer));
        state.Save(settings.State);

        AnsiConsole.MarkupLine($"[green]CRL #{state.CrlNumber}[/] with {state.Revoked.Count} entr{(state.Revoked.Count == 1 ? "y" : "ies")} " +
            $"written to [blue]{settings.Out}[/] (next update in {settings.Days} days).");

        return 0;
    }
}
