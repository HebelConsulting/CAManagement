using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace Pkcs11Interop.Extensions;

public static class InlineArrayExtensions
{
    private static ILogger GetLogger(IServiceProvider serviceProvider) => serviceProvider?.GetService<ILoggerFactory>()
        ?.CreateLogger(type: MethodBase.GetCurrentMethod()!.DeclaringType!)!;
}