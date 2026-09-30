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

        [CommandOption("--manifest <FILE>")]
        [Description("Also record the revocation in this enrolment manifest, so SimplArchive's import can "
            + "withdraw the certificate it enrolled (#21).")]
        public string? Manifest { get; init; }


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

        // ALREADY REVOKED IS NOT NOTHING TO DO where a manifest is being kept. The CA's own state is already
        // correct, but the manifest is a separate, later-added record — so a revocation performed before
        // manifests existed, or with the option omitted, must still be able to reach the consumer. Recording
        // it is an upsert by serial, so doing it twice changes nothing.
        var alreadyRevoked = state.Revoked.FirstOrDefault(r => r.SerialHex == serialHex);
        var revokedAt = alreadyRevoked?.RevokedAtUtc ?? DateTimeOffset.UtcNow;

        if (alreadyRevoked is null)
        {
            state.Revoked.Add(new CaStateFile.RevokedEntry(serialHex, revokedAt, settings.Reason));
            store.Save(state);
        }

        if (settings.Manifest is { Length: > 0 } manifestPath)
        {
            var manifest = EnrolmentManifest.Read(manifestPath);
            manifest.RecordRevoked(serialHex, revokedAt, settings.Reason.ToString());
            manifest.Write(manifestPath);
            AnsiConsole.MarkupLine($"[grey]Recorded in[/] [blue]{Markup.Escape(manifestPath)}[/].");
        }

        if (alreadyRevoked is not null)
        {
            AnsiConsole.MarkupLine($"[yellow]Serial {serialHex} was already revoked[/] "
                + $"({revokedAt:yyyy-MM-dd}){(settings.Manifest is null ? "." : "; the manifest now says so too.")}");
            return 0;
        }

        AnsiConsole.MarkupLine($"[green]Revoked[/] serial [yellow]{serialHex}[/] ({settings.Reason}); " +
            $"run [blue]gen-crl[/] to publish.");

        return 0;
    }
}
