using System.ComponentModel;
using CAManagement.Cli.Infrastructure;
using CAManagement.X509;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>
/// Stores an issued certificate on the token beside the key it belongs to, completing the enrolment loop
/// (<c>csr</c> → <c>issue</c> → here) without the card vendor's tooling.
/// </summary>
public sealed class ImportCertCommand : Command<ImportCertCommand.Settings>
{
    public sealed class Settings : HsmLoginSettings
    {
        [CommandOption("--label <LABEL>")]
        [Description("Label to store the certificate under — normally the label of the key it belongs to.")]
        public required string Label { get; init; }

        [CommandOption("--cert <FILE>")]
        [Description("The certificate to store, PEM or DER.")]
        public required string Cert { get; init; }

        public override ValidationResult Validate() => this switch
        {
            { Label: null or "" } => ValidationResult.Error("Missing required option --label."),
            { Cert: null or "" } => ValidationResult.Error("Missing required option --cert."),
            _ => base.Validate(),
        };
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var bytes = File.ReadAllBytes(settings.Cert);
        var der = Pem.TryDecodeFirst(System.Text.Encoding.UTF8.GetString(bytes)) is { } pem
            ? pem.Der          // PEM
            : bytes;           // already DER

        // The PKCS#11 layer deliberately does not parse certificates, so the subject DER is the caller's to
        // supply — and it must be the certificate's OWN subject, or the object is findable under a name that
        // is not its own.
        var certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(der);
        var subjectDer = certificate.SubjectName.RawData;

        using var hsm = new HsmCa();
        var session = hsm.OpenLoggedInSession(settings, settings.Pin);
        session.ImportX509Certificate(settings.Label, der, subjectDer);

        AnsiConsole.MarkupLine(
            $"[green]Certificate stored[/] on the token as '[blue]{Markup.Escape(settings.Label)}[/]' "
            + $"([blue]{Markup.Escape(certificate.Subject)}[/]).");

        return 0;
    }
}
