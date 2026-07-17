using CAConsole.Commands;
using CAConsole.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Pkcs11Interop.DependencyInjection;
using Spectre.Console;
using Spectre.Console.Cli;

var configuration = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

var services = new ServiceCollection();
services.AddPkcs11(configuration);
services.AddTransient<HsmCa>();

var app = new CommandApp(new TypeRegistrar(services));
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
