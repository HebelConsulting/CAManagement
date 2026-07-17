using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

namespace CAConsole.Infrastructure;

/// <summary>Bridges Spectre.Console.Cli's DI abstraction to Microsoft.Extensions.DependencyInjection.</summary>
public sealed class TypeRegistrar(IServiceCollection builder) : ITypeRegistrar
{
    public ITypeResolver Build() => new TypeResolver(builder.BuildServiceProvider());

    public void Register(Type service, Type implementation) => builder.AddSingleton(service, implementation);

    public void RegisterInstance(Type service, object implementation) => builder.AddSingleton(service, implementation);

    public void RegisterLazy(Type service, Func<object> factory) => builder.AddSingleton(service, _ => factory());
}
