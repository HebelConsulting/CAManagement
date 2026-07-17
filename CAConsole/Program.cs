using CAConsole.Commands;
using CAConsole.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Pkcs11Interop.DependencyInjection;
using Spectre.Console.Cli;

var configuration = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

var services = new ServiceCollection();
services.AddPkcs11(configuration);

var app = new CommandApp(new TypeRegistrar(services));
app.Configure(config =>
{
    config.SetApplicationName("caconsole");
    config.AddCommand<InfoCommand>("info")
        .WithDescription("Load the PKCS#11 module and show token/session info.");
});

return app.Run(args);
