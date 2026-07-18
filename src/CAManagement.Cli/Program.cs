using CAManagement.Cli.Commands;
using CAManagement.Cli.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console;
using Spectre.Console.Cli;

// All configuration is passed as CLI options with educated defaults (see
// HsmSettings); there is no configuration file.
var app = new CommandApp(new TypeRegistrar(new ServiceCollection()));
app.Configure(config =>
{
    config.SetApplicationName("caconsole");
    config.SetExceptionHandler((exception, _) =>
    {
        AnsiConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(exception.GetBaseException().Message)}");
        return 1;
    });

    config.AddCommand<InfoCommand>("info")
        .WithDescription("Load the PKCS#11 module and show token/session info.");
    config.AddCommand<AsnCommand>("asn")
        .WithDescription("Analyze a certificate, CSR, CRL or key file as an annotated ASN.1 tree.");
    config.AddCommand<InitCaCommand>("init-ca")
        .WithDescription("Generate a CA key pair on the token and write a self-signed root certificate.");
    config.AddCommand<IssueCommand>("issue")
        .WithDescription("Issue a certificate from a PKCS#10 CSR using the token-resident CA key.");
    config.AddCommand<RevokeCommand>("revoke")
        .WithDescription("Record a certificate revocation in the CA state file.");
    config.AddCommand<GenCrlCommand>("gen-crl")
        .WithDescription("Sign a CRL from the CA state file using the token-resident CA key.");
    config.AddCommand<OcspRespondCommand>("ocsp-respond")
        .WithDescription("Answer OCSP requests (file mode or HTTP) from the CA state file.");
});

return app.Run(args);
