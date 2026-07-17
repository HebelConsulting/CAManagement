using System.ComponentModel;
using CAConsole.Infrastructure;
using CertificateAuthority;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAConsole.Commands;

/// <summary>Records a revocation in the CA state file (published with gen-crl).</summary>
public sealed class RevokeCommand : Command<RevokeCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [CommandOption("--serial <HEX>")]
        [Description("Serial number of the certificate to revoke (hex).")]
        public required string Serial { get; init; }

        [CommandOption("--reason <REASON>")]
        [DefaultValue(RevocationReason.Unspecified)]
        public RevocationReason Reason { get; init; } = RevocationReason.Unspecified;

        [CommandOption("--state <FILE>")]
        [DefaultValue("ca-state.json")]
        public string State { get; init; } = "ca-state.json";
    }

    public override int Execute(CommandContext context, Settings settings)
    {
        var serial = Convert.FromHexString(settings.Serial.Length % 2 == 0 ? settings.Serial : $"0{settings.Serial}");
        var serialHex = Convert.ToHexString(serial);

        var state = CaStateFile.Load(settings.State);

        if (state.Revoked.Any(r => r.SerialHex == serialHex))
        {
            AnsiConsole.MarkupLine($"[yellow]Serial {serialHex} is already revoked.[/]");
            return 0;
        }

        state.Revoked.Add(new CaStateFile.RevokedEntry(serialHex, DateTimeOffset.UtcNow, settings.Reason));
        state.Save(settings.State);

        AnsiConsole.MarkupLine($"[green]Revoked[/] serial [yellow]{serialHex}[/] ({settings.Reason}); " +
            $"run [blue]gen-crl[/] to publish.");

        return 0;
    }
}
