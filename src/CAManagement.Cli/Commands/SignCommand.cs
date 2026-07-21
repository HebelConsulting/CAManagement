using System.ComponentModel;
using CAManagement.Cli.Infrastructure;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Signs a file with a token private key using multi-part signing (C_SignUpdate/C_SignFinal).</summary>
public sealed class SignCommand : Command<SignCommand.Settings>
{
    public sealed class Settings : HsmLoginSettings
    {
        [CommandOption("--key-label <LABEL>")]
        [Description("Label of the private key on the token.")]
        public required string KeyLabel { get; init; }

        [CommandOption("--in <FILE>")]
        [Description("File to sign.")]
        public required string In { get; init; }

        [CommandOption("--out <FILE>")]
        [Description("Where to write the signature.")]
        public required string Out { get; init; }

        [CommandOption("--mechanism <MECHANISM>")]
        [Description("Signing mechanism (must be a multi-part/hashing mechanism).")]
        [DefaultValue(CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS)]
        public CK_MECHANISM_TYPE Mechanism { get; init; } = CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS;
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var hsm = new HsmCa();
        var session = hsm.OpenLoggedInSession(settings, settings.Pin);
        var privateKey = SingleKey(session.FindObjects(CK_OBJECT_CLASS.CKO_PRIVATE_KEY, settings.KeyLabel), settings.KeyLabel);

        byte[] signature;
        using (var stream = File.OpenRead(settings.In))
        {
            signature = session.SignParts(settings.Mechanism, FileChunks.Read(stream), privateKey);
        }

        File.WriteAllBytes(settings.Out, signature);
        AnsiConsole.MarkupLine($"[green]Signed[/] [blue]{Markup.Escape(settings.In)}[/] with '{Markup.Escape(settings.KeyLabel)}' " +
            $"({settings.Mechanism}); {signature.Length}-byte signature written to [blue]{settings.Out}[/].");

        return 0;
    }

    internal static NativeULong SingleKey(IReadOnlyList<NativeULong> handles, string label) => handles.Count switch
    {
        1 => handles[0],
        0 => throw new InvalidOperationException($"No key with label '{label}' found on the token."),
        _ => throw new InvalidOperationException($"Multiple keys with label '{label}' found on the token."),
    };
}
