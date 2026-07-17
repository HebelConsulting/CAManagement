using System.ComponentModel;
using Pkcs11Interop;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAConsole.Commands;

/// <summary>Loads the configured PKCS#11 module and prints token/session info.</summary>
public sealed class InfoCommand(Pkcs11Library library) : Command<InfoCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [CommandOption("--read-write")]
        [Description("Open a read-write session instead of read-only.")]
        public bool ReadWrite { get; init; }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        AnsiConsole.MarkupLine($"[green]Loaded PKCS#11 module[/] (Cryptoki {library.CryptokiVersion}).");

        using var session = library.OpenSession(settings.ReadWrite);
        AnsiConsole.MarkupLine($"Opened session [blue]{session.Handle}[/] on slot [blue]{session.Slot}[/].");

        return 0;
    }
}
