using System.ComponentModel;
using CAManagement.Pkcs11.Configuration;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Infrastructure;

/// <summary>
/// Common HSM connection options for commands that talk to the token. All have
/// educated defaults: the module falls back to the platform's SoftHSM2 location,
/// the token to the first slot with a token present, and the PIN to an
/// interactive secret prompt.
/// </summary>
public class HsmSettings : CommandSettings
{
    [CommandOption("--module <PATH>")]
    [Description("PKCS#11 module path. Default: the platform's SoftHSM2 location.")]
    public string? Module { get; init; }

    [CommandOption("--token-label <LABEL>")]
    [Description("Token to use. Default: the first slot with a token present.")]
    public string? TokenLabel { get; init; }

    [CommandOption("--slot <ID>")]
    [Description("Explicit slot id (overrides --token-label).")]
    public ulong? Slot { get; init; }

    internal Pkcs11Options ToPkcs11Options()
    {
        var options = new Pkcs11Options
        {
            TokenLabel = TokenLabel,
            SlotId = Slot,
        };

        if (Module is { } module)
        {
            options.ModulePath = module; // otherwise keep the per-OS default
        }

        return options;
    }
}

/// <summary>Settings for commands that log in to the token — the PIN is mandatory.</summary>
public class HsmLoginSettings : HsmSettings
{
    [CommandOption("--pin <PIN>")]
    [Description("User PIN (required).")]
    public required string Pin { get; init; }

    // Spectre constructs settings via reflection and does not enforce the C#
    // `required` modifier — validate explicitly.
    public override ValidationResult Validate() => string.IsNullOrEmpty(Pin)
        ? ValidationResult.Error("Missing required option --pin.")
        : base.Validate();
}
