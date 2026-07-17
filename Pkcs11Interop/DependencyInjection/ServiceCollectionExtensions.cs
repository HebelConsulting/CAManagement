using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Pkcs11Interop.Configuration;

namespace Pkcs11Interop.DependencyInjection;

/// <summary>Registers the PKCS#11 library via <c>IOptions&lt;Pkcs11Options&gt;</c> (SPEC #5).</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddPkcs11(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<Pkcs11Options>(configuration.GetSection(Pkcs11Options.SectionName));
        services.AddSingleton<Pkcs11Library>();

        return services;
    }

    public static IServiceCollection AddPkcs11(this IServiceCollection services, Action<Pkcs11Options> configure)
    {
        services.Configure(configure);
        services.AddSingleton<Pkcs11Library>();

        return services;
    }
}
