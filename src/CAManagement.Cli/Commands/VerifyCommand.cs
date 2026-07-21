using System.ComponentModel;
using CAManagement.Cli.Infrastructure;
using CAManagement.Pkcs11.DataStructures;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Verifies a file's signature with a token public key using multi-part verification.</summary>
public sealed class VerifyCommand : Command<VerifyCommand.Settings>
{
    public sealed class Settings : HsmLoginSettings
    {
        [CommandOption("--key-label <LABEL>")]
        [Description("Label of the public key on the token.")]
        public required string KeyLabel { get; init; }

        [CommandOption("--in <FILE>")]
        [Description("The file that was signed.")]
        public required string In { get; init; }

        [CommandOption("--sig <FILE>")]
        [Description("The signature to check.")]
        public required string Sig { get; init; }

        [CommandOption("--mechanism <MECHANISM>")]
        [Description("Signing mechanism (must match how it was signed).")]
        [DefaultValue(CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS)]
        public CK_MECHANISM_TYPE Mechanism { get; init; } = CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS;
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var hsm = new HsmCa();
        var session = hsm.OpenLoggedInSession(settings, settings.Pin);
        var publicKey = SignCommand.SingleKey(session.FindObjects(CK_OBJECT_CLASS.CKO_PUBLIC_KEY, settings.KeyLabel), settings.KeyLabel);
        var signature = File.ReadAllBytes(settings.Sig);

        bool valid;
        using (var stream = File.OpenRead(settings.In))
        {
            valid = session.VerifyParts(settings.Mechanism, FileChunks.Read(stream), signature, publicKey);
        }

        if (valid)
        {
            AnsiConsole.MarkupLine($"[green]Signature valid[/] for [blue]{Markup.Escape(settings.In)}[/].");
            return 0;
        }

        AnsiConsole.MarkupLine($"[red]Signature INVALID[/] for [blue]{Markup.Escape(settings.In)}[/].");
        return 1;
    }
}
