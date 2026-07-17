using System.Runtime.InteropServices;
using Pkcs11Interop;
using Pkcs11Interop.DataStructures;

namespace CAManagementTests.Unit;

public sealed class NativeAllocationScopeTests
{
    [Fact]
    public void Bool_attribute_is_a_single_byte()
    {
        using var scope = new NativeAllocationScope();

        var attribute = scope.Attribute(CK_ATTRIBUTE_TYPE.CKA_TOKEN, true);

        Assert.Equal(CK_ATTRIBUTE_TYPE.CKA_TOKEN, attribute.Type);
        Assert.Equal(1UL, attribute.ValueLength);
        Assert.NotEqual(IntPtr.Zero, attribute.Value);
        Assert.Equal(1, Marshal.ReadByte(attribute.Value));
    }

    [Fact]
    public void Ulong_attribute_is_eight_little_endian_bytes()
    {
        using var scope = new NativeAllocationScope();

        var attribute = scope.Attribute(CK_ATTRIBUTE_TYPE.CKA_MODULUS_BITS, 2048UL);

        Assert.Equal(8UL, attribute.ValueLength);
        Assert.Equal(2048UL, (ulong)Marshal.ReadInt64(attribute.Value));
    }

    [Fact]
    public void Object_class_attribute_carries_the_enum_value()
    {
        using var scope = new NativeAllocationScope();

        var attribute = scope.Attribute(CK_ATTRIBUTE_TYPE.CKA_CLASS, CK_OBJECT_CLASS.CKO_PRIVATE_KEY);

        Assert.Equal(8UL, attribute.ValueLength);
        Assert.Equal((ulong)CK_OBJECT_CLASS.CKO_PRIVATE_KEY, (ulong)Marshal.ReadInt64(attribute.Value));
    }
}
