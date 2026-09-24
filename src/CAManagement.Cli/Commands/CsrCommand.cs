using System.ComponentModel;
using CAManagement.Cli.Infrastructure;
using CAManagement.X509;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>
/// Builds a PKCS#10 certificate request signed by a key that stays on the token — the enrolment step that had
/// no home here: <c>issue</c> could sign a request, and nothing could produce one.
/// </summary>
/// <remarks>
/// Why it matters beyond convenience: turning a token-resident key into a certificate otherwise needs the
/// card vendor's own tool, which is per-vendor and therefore per-customer. This is PKCS#11, so it works with
/// any card the module can drive.
/// </remarks>
public sealed class CsrCommand : Command<CsrCommand.Settings>
{
    public sealed class Settings : HsmLoginSettings
    {
        [CommandOption("--label <LABEL>")]
        [Description("Label of the key ON THE TOKEN that the request is for, and that signs it.")]
        public required string Label { get; init; }

        [CommandOption("--subject <SUBJECT>")]
        [Description("Subject DN, e.g. \"C=CH, O=Example, CN=Card Holder\".")]
        public required string Subject { get; init; }

        [CommandOption("--out <FILE>")]
        [Description("Where to write the PEM request.")]
        public required string Out { get; init; }

        public override ValidationResult Validate() => this switch
        {
            { Label: null or "" } => ValidationResult.Error("Missing required option --label."),
            { Subject: null or "" } => ValidationResult.Error("Missing required option --subject."),
            { Out: null or "" } => ValidationResult.Error("Missing required option --out."),
            _ => base.Validate(),
        };
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var hsm = new HsmCa();
        var session = hsm.OpenLoggedInSession(settings, settings.Pin);

        // The same pair the CA uses to sign certificates: a signer that delegates to the token, and the
        // public half to put in the request. The private key is never read, here or anywhere.
        var (signer, spki) = hsm.LoadCaKey(session, settings.Label);

        var der = new CertificateSigningRequestBuilder
        {
            Subject = SubjectParser.Parse(settings.Subject),
            SubjectPublicKeyInfo = spki,
        }.Sign(signer);

        File.WriteAllText(settings.Out, Pem.Encode("CERTIFICATE REQUEST", der));

        AnsiConsole.MarkupLine(
            $"[green]Request written[/] to [blue]{Markup.Escape(settings.Out)}[/] for key "
            + $"'[blue]{Markup.Escape(settings.Label)}[/]', signed on the token.");
        AnsiConsole.MarkupLine("Sign it with [blue]issue[/], then put the certificate back with [blue]import-cert[/].");

        return 0;
    }
}
