using System.ComponentModel;
using CAManagement.Cli.Infrastructure;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Extensions;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>
/// Re-initializes a token in place (<c>C_InitToken</c>): every object on it is destroyed and it is
/// relabelled. Deliberately not called <c>delete-token</c> — PKCS#11 has no delete-token operation,
/// the slot remains afterwards, and a verb that claimed to remove one would be lying about what the
/// standard can do. Removing the slot itself is backend-specific file surgery (SoftHSM's token
/// directory), which this tool does not do.
/// </summary>
public sealed class WipeTokenCommand : Command<WipeTokenCommand.Settings>
{
    public sealed class Settings : HsmSettings
    {
        [CommandOption("--so-pin <PIN>")]
        [Description("Security Officer PIN of the token being wiped (the one it was initialized with).")]
        public required string SoPin { get; init; }

        [CommandOption("--new-label <LABEL>")]
        [Description("Label to leave behind (max 32 bytes). Required: a wiped token that kept its old label would still collide with the duplicates it was wiped to resolve.")]
        public required string NewLabel { get; init; }

        [CommandOption("--yes")]
        [Description("Confirm the wipe. Without it nothing is destroyed.")]
        public bool Yes { get; init; }

        // Spectre constructs settings by reflection and does not enforce `required` — validate explicitly.
        public override ValidationResult Validate() => this switch
        {
            { Slot: null } => ValidationResult.Error(
                "Specify --slot. A token is wiped by slot id, never by label: the usual reason to wipe one is that "
                + "its label is ambiguous, and resolving by label would pick between the duplicates at random."),
            { TokenLabel: not null } => ValidationResult.Error(
                "--token-label is not accepted here; address the token by --slot."),
            { SoPin: null or "" } => ValidationResult.Error("Missing required option --so-pin."),
            { NewLabel: null or "" } => ValidationResult.Error("Missing required option --new-label."),
            { Yes: false } => ValidationResult.Error(
                "Refusing to wipe without --yes: C_InitToken destroys every key on the token, and there is no undo."),
            _ => base.Validate(),
        };
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var library = new Pkcs11Library(settings.ToPkcs11Options());

        var slot = settings.Slot!.Value;
        var before = library.GetTokenInfo(slot);

        if (!before.Flags.HasFlag(CK_TOKEN_INFO_FLAGS.CKF_TOKEN_INITIALIZED))
        {
            AnsiConsole.MarkupLine($"[yellow]Slot[/] [blue]{slot}[/] [yellow]holds no initialized token[/] — nothing to wipe.");
            return 0;
        }

        var oldLabel = before.Label.AsPkcs11String();

        // C_InitToken requires that no session is open on the slot.
        library.CloseAllSessions(slot);
        library.InitializeToken(slot, settings.SoPin, settings.NewLabel);

        AnsiConsole.MarkupLine(
            $"[green]Wiped token[/] '[blue]{Markup.Escape(oldLabel)}[/]' on slot [blue]{slot}[/] — every object on it is "
            + $"destroyed and it is now labelled '[blue]{Markup.Escape(settings.NewLabel)}[/]'.");
        AnsiConsole.MarkupLine(
            "[yellow]The slot remains[/] (PKCS#11 cannot remove one) and the token now has [yellow]no user PIN[/] — "
            + "run [blue]init-token[/] against it before use, or leave it parked under its new label.");

        return 0;
    }
}
