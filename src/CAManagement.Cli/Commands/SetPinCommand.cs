using System.ComponentModel;
using CAManagement.Cli.Infrastructure;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Changes the user PIN (<c>C_SetPIN</c>). <c>--pin</c> is the current PIN.</summary>
public sealed class SetPinCommand : Command<SetPinCommand.Settings>
{
    public sealed class Settings : HsmLoginSettings
    {
        [CommandOption("--new-pin <PIN>")]
        [Description("The new user PIN.")]
        public required string NewPin { get; init; }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var hsm = new HsmCa();
        var session = hsm.OpenLoggedInSession(settings, settings.Pin);

        session.SetPin(settings.Pin, settings.NewPin);

        AnsiConsole.MarkupLine("[green]User PIN changed.[/]");

        return 0;
    }
}
