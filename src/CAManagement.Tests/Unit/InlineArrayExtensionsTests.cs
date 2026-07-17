using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Extensions;

namespace CAManagement.Tests.Unit;

public sealed class InlineArrayExtensionsTests
{
    [Fact]
    public void Trims_space_padding_from_pkcs11_label()
    {
        var array = new InlineArray32();
        Fill(ref array, "ca-test");

        Assert.Equal("ca-test", array.AsPkcs11String());
    }

    [Fact]
    public void Empty_field_becomes_empty_string()
    {
        var array = new InlineArray16();
        Fill16(ref array, "");

        Assert.Equal(string.Empty, array.AsPkcs11String());
    }

    private static void Fill(ref InlineArray32 array, string text)
    {
        for (var i = 0; i < 32; i++)
        {
            array[i] = (byte)(i < text.Length ? text[i] : ' ');
        }
    }

    private static void Fill16(ref InlineArray16 array, string text)
    {
        for (var i = 0; i < 16; i++)
        {
            array[i] = (byte)(i < text.Length ? text[i] : ' ');
        }
    }
}
