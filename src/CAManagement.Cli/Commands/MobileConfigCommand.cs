using System.ComponentModel;
using CAManagement.X509;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>
/// Builds an Apple configuration profile (.mobileconfig) from certificate material on disk: an optional
/// PKCS#12 identity plus any number of trusted root certificates — the one-tap install path for iOS/
/// iPadOS/macOS devices. Pure file-in/file-out: no token, no PKCS#11.
/// </summary>
public sealed class MobileConfigCommand : Command<MobileConfigCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [CommandOption("--out <FILE>")]
        [Description("Output path for the .mobileconfig profile.")]
        public required string Out { get; init; }

        [CommandOption("--name <NAME>")]
        [Description("Profile display name, shown on the device at install.")]
        public required string Name { get; init; }

        [CommandOption("--identifier <ID>")]
        [Description("Reverse-DNS profile identifier. Default: derived from the output file name.")]
        public string? Identifier { get; init; }

        [CommandOption("--identity <P12>")]
        [Description("PKCS#12 identity file to embed (com.apple.security.pkcs12 payload).")]
        public string? Identity { get; init; }

        [CommandOption("--password <PASSWORD>")]
        [Description("The PKCS#12 password. Embedded in the profile so the install does not prompt — "
            + "whoever holds the file holds the identity; hand it over accordingly.")]
        public string? Password { get; init; }

        [CommandOption("--root <FILE>")]
        [Description("Trusted root certificate to embed (PEM or DER; repeatable).")]
        public string[] Roots { get; init; } = [];

        public override ValidationResult Validate()
        {
            if (Identity is null && Roots.Length == 0)
            {
                return ValidationResult.Error("Nothing to embed: pass --identity and/or at least one --root.");
            }

            return Identity is not null && Password is null
                ? ValidationResult.Error("--identity needs --password (the PKCS#12 password).")
                : ValidationResult.Success();
        }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var identifier = settings.Identifier
            ?? $"camanagement.profile.{Path.GetFileNameWithoutExtension(settings.Out).ToLowerInvariant()}";
        var profile = new MobileConfigProfile(settings.Name, identifier);

        if (settings.Identity is { } identityPath)
        {
            profile.AddIdentity(File.ReadAllBytes(identityPath), settings.Password!,
                $"{settings.Name} identity", $"{identifier}.identity");
        }

        var rootIndex = 0;
        foreach (var rootPath in settings.Roots)
        {
            rootIndex++;
            profile.AddRootCertificate(LoadCertificateDer(rootPath),
                $"{settings.Name} root {rootIndex}", $"{identifier}.root{rootIndex}");
        }

        File.WriteAllText(settings.Out, profile.Build());
        AnsiConsole.MarkupLine($"Profile written to [bold green]{Markup.Escape(settings.Out)}[/] "
            + $"({(settings.Identity is null ? 0 : 1)} identity, {settings.Roots.Length} root(s)).");
        return 0;
    }

    private static byte[] LoadCertificateDer(string path)
    {
        var bytes = File.ReadAllBytes(path);
        if (bytes.AsSpan().IndexOf("-----BEGIN"u8) < 0)
        {
            return bytes; // raw DER
        }

        var blocks = Pem.DecodeAll(System.Text.Encoding.UTF8.GetString(bytes));
        return blocks.Count switch
        {
            1 => blocks[0].Der,
            0 => throw new FormatException($"'{path}' contains no decodable PEM block."),
            _ => throw new FormatException($"'{path}' contains {blocks.Count} PEM blocks — pass each root as its own --root."),
        };
    }
}
