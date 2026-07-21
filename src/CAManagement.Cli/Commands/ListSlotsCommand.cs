using CAManagement.Cli.Infrastructure;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Extensions;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Enumerates slots, tokens and supported mechanisms (like <c>softhsm2-util --show-slots</c>).</summary>
public sealed class ListSlotsCommand : Command<ListSlotsCommand.Settings>
{
    public sealed class Settings : HsmSettings
    {
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var library = new Pkcs11Library(settings.ToPkcs11Options());

        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Slot");
        table.AddColumn("Token");
        table.AddColumn("Initialized");
        table.AddColumn("Mechanisms");

        foreach (var slot in library.GetSlotList(tokenPresent: false))
        {
            var slotInfo = library.GetSlotInfo(slot);

            if (!slotInfo.Flags.HasFlag(CK_SLOT_INFO_FLAGS.CKF_TOKEN_PRESENT))
            {
                table.AddRow(slot.ToString(), "[dim](no token)[/]", "-", "-");
                continue;
            }

            var tokenInfo = library.GetTokenInfo(slot);
            var initialized = tokenInfo.Flags.HasFlag(CK_TOKEN_INFO_FLAGS.CKF_TOKEN_INITIALIZED);
            var label = tokenInfo.Label.AsPkcs11String();

            table.AddRow(
                slot.ToString(),
                string.IsNullOrEmpty(label) ? "[dim](unnamed)[/]" : Markup.Escape(label),
                initialized ? "[green]yes[/]" : "[yellow]no[/]",
                library.GetMechanismList(slot).Length.ToString());
        }

        AnsiConsole.MarkupLine($"[green]Loaded PKCS#11 module[/] (Cryptoki {library.CryptokiVersion}).");
        AnsiConsole.Write(table);

        return 0;
    }
}
