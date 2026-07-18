using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using CAManagement.Cli.Infrastructure;
using CAManagement.X509;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Signs a CRL from the CA state file with the token-resident CA key.</summary>
public sealed class GenCrlCommand : Command<GenCrlCommand.Settings>
{
    public sealed class Settings : HsmSettings
    {
        [CommandOption("--ca-label <LABEL>")]
        [Description("Token label of the CA key pair.")]
        public required string CaLabel { get; init; }

        [CommandOption("--ca-cert <FILE>")]
        [Description("The CA certificate (PEM or DER); its subject becomes the CRL issuer.")]
        public required string CaCert { get; init; }

        [CommandOption("--state <FILE|token>")]
        [Description("CA state file path, or 'token' to keep state as a data object on the HSM token.")]
        [DefaultValue("ca-state.json")]
        public string State { get; init; } = "ca-state.json";

        [CommandOption("--days <DAYS>")]
        [Description("Days until nextUpdate.")]
        [DefaultValue(7)]
        public int Days { get; init; } = 7;

        [CommandOption("--out <FILE>")]
        [DefaultValue("ca.crl")]
        public string Out { get; init; } = "ca.crl";

    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var hsm = new HsmCa();
        var session = hsm.OpenLoggedInSession(settings);
        var (signer, caSpki) = hsm.LoadCaKey(session, settings.CaLabel);

        // The CRL issuer is the CA certificate's subject (byte-faithful extraction).
        var issuer = X509Names.SubjectOf(File.ReadAllBytes(settings.CaCert));

        ICaStateStore store = CaStateStores.IsToken(settings.State)
            ? new TokenCaStateStore(session, settings.CaLabel)
            : new FileCaStateStore(settings.State);
        var state = store.Load();
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
        store.Save(state);

        AnsiConsole.MarkupLine($"[green]CRL #{state.CrlNumber}[/] with {state.Revoked.Count} entr{(state.Revoked.Count == 1 ? "y" : "ies")} " +
            $"written to [blue]{settings.Out}[/] (next update in {settings.Days} days).");

        return 0;
    }
}
