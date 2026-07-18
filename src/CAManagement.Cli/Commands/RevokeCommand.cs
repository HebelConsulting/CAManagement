using System.ComponentModel;
using CAManagement.Cli.Infrastructure;
using CAManagement.X509;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Records a revocation in the CA state (published with gen-crl).</summary>
public sealed class RevokeCommand : Command<RevokeCommand.Settings>
{
    public sealed class Settings : HsmSettings
    {
        [CommandOption("--serial <HEX>")]
        [Description("Serial number of the certificate to revoke (hex).")]
        public required string Serial { get; init; }

        [CommandOption("--reason <REASON>")]
        [DefaultValue(RevocationReason.Unspecified)]
        public RevocationReason Reason { get; init; } = RevocationReason.Unspecified;

        [CommandOption("--state <FILE|token>")]
        [Description("CA state file path, or 'token' to keep state as a data object on the HSM token.")]
        [DefaultValue("ca-state.json")]
        public string State { get; init; } = "ca-state.json";

        [CommandOption("--ca-label <LABEL>")]
        [Description("Token label of the CA key pair (required with --state token).")]
        public string? CaLabel { get; init; }

        [CommandOption("--pin <PIN>")]
        [Description("User PIN (required with --state token).")]
        public string? Pin { get; init; }


        public override ValidationResult Validate() =>
            CaStateStores.IsToken(State) && (CaLabel is null || Pin is null)
                ? ValidationResult.Error("--state token requires --ca-label and --pin.")
                : ValidationResult.Success();
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var hsm = new HsmCa();
        ICaStateStore store = CaStateStores.IsToken(settings.State)
            ? new TokenCaStateStore(hsm.OpenLoggedInSession(settings, settings.Pin!), settings.CaLabel!)
            : new FileCaStateStore(settings.State);

        var serial = Convert.FromHexString(settings.Serial.Length % 2 == 0 ? settings.Serial : $"0{settings.Serial}");
        var serialHex = Convert.ToHexString(serial);

        var state = store.Load();

        if (state.Revoked.Any(r => r.SerialHex == serialHex))
        {
            AnsiConsole.MarkupLine($"[yellow]Serial {serialHex} is already revoked.[/]");
            return 0;
        }

        state.Revoked.Add(new CaStateFile.RevokedEntry(serialHex, DateTimeOffset.UtcNow, settings.Reason));
        store.Save(state);

        AnsiConsole.MarkupLine($"[green]Revoked[/] serial [yellow]{serialHex}[/] ({settings.Reason}); " +
            $"run [blue]gen-crl[/] to publish.");

        return 0;
    }
}
