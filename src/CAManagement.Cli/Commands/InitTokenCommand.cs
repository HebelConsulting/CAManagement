using System.ComponentModel;
using CAManagement.Cli.Infrastructure;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Initializes a token (SO PIN + label) and sets its user PIN — like <c>softhsm2-util --init-token</c>.</summary>
public sealed class InitTokenCommand : Command<InitTokenCommand.Settings>
{
    public sealed class Settings : HsmLoginSettings
    {
        [CommandOption("--label <LABEL>")]
        [Description("Token label (max 32 bytes).")]
        public required string Label { get; init; }

        [CommandOption("--so-pin <PIN>")]
        [Description("Security Officer PIN.")]
        public required string SoPin { get; init; }

        [CommandOption("--free")]
        [Description("Initialize the first free (uninitialized) slot instead of --slot.")]
        public bool Free { get; init; }

        public override ValidationResult Validate()
        {
            if (base.Validate() is { Successful: false } baseResult)
            {
                return baseResult; // --pin (the user PIN to set) is mandatory
            }

            return Free == Slot.HasValue
                ? ValidationResult.Error("Specify exactly one of --free or --slot.")
                : ValidationResult.Success();
        }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var library = new Pkcs11Library(settings.ToPkcs11Options());

        var slot = settings.Free ? library.FindFreeSlot() : settings.Slot!.Value;

        library.InitializeToken(slot, settings.SoPin, settings.Label);

        // Set the user PIN from an SO session (C_InitPIN).
        using (var session = library.OpenSession(slot, readWrite: true))
        using (session.Login(settings.SoPin, CKU.CKU_SO))
        {
            session.InitializeUserPin(settings.Pin);
        }

        AnsiConsole.MarkupLine($"[green]Initialized token[/] '[blue]{Markup.Escape(settings.Label)}[/]' on slot [blue]{slot}[/] " +
            "with an SO PIN and user PIN.");

        return 0;
    }
}
