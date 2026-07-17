using System.ComponentModel;
using CAManagement.Cli.Infrastructure;
using CAManagement.X509;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>Generates a CA key pair on the token and writes a self-signed root certificate.</summary>
public sealed class InitCaCommand(HsmCa hsm) : Command<InitCaCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [CommandOption("--label <LABEL>")]
        [Description("Token label for the CA key pair.")]
        public required string Label { get; init; }

        [CommandOption("--subject <SUBJECT>")]
        [Description("CA subject, e.g. \"C=CH, O=Example, CN=Example Root CA\" (encoded in the given order).")]
        public required string Subject { get; init; }

        [CommandOption("--key-type <TYPE>")]
        [Description("ec (P-256, default) or rsa (2048).")]
        [DefaultValue("ec")]
        public string KeyType { get; init; } = "ec";

        [CommandOption("--years <YEARS>")]
        [DefaultValue(10)]
        public int Years { get; init; } = 10;

        [CommandOption("--out <FILE>")]
        [Description("Output path for the CA certificate (PEM).")]
        [DefaultValue("ca.crt")]
        public string Out { get; init; } = "ca.crt";

        [CommandOption("--pin <PIN>")]
        public string? Pin { get; init; }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var hsmScope = hsm;
        var session = hsm.OpenLoggedInSession(settings.Pin);

        if (session.FindObjects(CAManagement.Pkcs11.DataStructures.CK_OBJECT_CLASS.CKO_PRIVATE_KEY, settings.Label).Count > 0)
        {
            throw new InvalidOperationException($"A key with label '{settings.Label}' already exists on the token.");
        }

        _ = settings.KeyType.ToLowerInvariant() switch
        {
            "ec" => session.GenerateEcKeyPair(settings.Label),
            "rsa" => session.GenerateRsaKeyPair(settings.Label),
            var other => throw new NotSupportedException($"Unsupported key type '{other}' (use ec or rsa)."),
        };

        var (signer, spki) = hsm.LoadCaKey(session, settings.Label);
        var subject = SubjectParser.Parse(settings.Subject);

        var certificateDer = new CertificateBuilder
        {
            Subject = subject,
            SubjectPublicKeyInfo = spki,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddYears(settings.Years),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: true, pathLengthConstraint: 0),
                CertificateExtensions.KeyUsage(KeyUsages.KeyCertSign | KeyUsages.CrlSign),
                CertificateExtensions.SubjectKeyIdentifier(spki.ComputeKeyIdentifier()),
            ],
        }.SignSelfSigned(signer);

        File.WriteAllText(settings.Out, Pem.Encode("CERTIFICATE", certificateDer));

        AnsiConsole.MarkupLine($"[green]CA initialized[/]: key '[blue]{settings.Label}[/]' ({settings.KeyType}) on the token, " +
            $"certificate written to [blue]{settings.Out}[/] ({subject}).");

        return 0;
    }
}
