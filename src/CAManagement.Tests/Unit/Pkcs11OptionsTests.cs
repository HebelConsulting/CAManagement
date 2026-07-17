using CAManagement.Pkcs11.Configuration;

namespace CAManagement.Tests.Unit;

public sealed class Pkcs11OptionsTests
{
    [Fact]
    public void Defaults_are_sensible()
    {
        var options = new Pkcs11Options();

        Assert.False(string.IsNullOrWhiteSpace(options.ModulePath));
        Assert.True(options.UseOsLocking);
        Assert.Null(options.SlotId);
        Assert.Null(options.TokenLabel);
    }

    [Fact]
    public void Section_name_is_pkcs11()
    {
        Assert.Equal("Pkcs11", Pkcs11Options.SectionName);
    }
}
