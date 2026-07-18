using System.ComponentModel;
using CAManagement.Cli.Infrastructure;
using CAManagement.Pkcs11;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Loads the PKCS#11 module and prints token/session info (no login).</summary>
public sealed class InfoCommand : Command<InfoCommand.Settings>
{
    public sealed class Settings : HsmSettings
    {
        [CommandOption("--read-write")]
        [Description("Open a read-write session instead of read-only.")]
        public bool ReadWrite { get; init; }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var library = new Pkcs11Library(settings.ToPkcs11Options());
        AnsiConsole.MarkupLine($"[green]Loaded PKCS#11 module[/] (Cryptoki {library.CryptokiVersion}).");

        using var session = library.OpenSession(settings.ReadWrite);
        AnsiConsole.MarkupLine($"Opened session [blue]{session.Handle}[/] on slot [blue]{session.Slot}[/].");

        return 0;
    }
}
