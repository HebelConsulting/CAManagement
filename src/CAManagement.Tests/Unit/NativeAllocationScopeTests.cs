using System.Runtime.InteropServices;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;

namespace CAManagement.Tests.Unit;

public sealed class NativeAllocationScopeTests
{
    [Fact]
    public void Bool_attribute_is_a_single_byte()
    {
        using var scope = new NativeAllocationScope();

        var attribute = scope.Attribute(CK_ATTRIBUTE_TYPE.CKA_TOKEN, true);

        Assert.Equal(CK_ATTRIBUTE_TYPE.CKA_TOKEN, attribute.Type);
        Assert.Equal((NativeULong)1, attribute.ValueLength);
        Assert.NotEqual(IntPtr.Zero, attribute.Value);
        Assert.Equal(1, Marshal.ReadByte(attribute.Value));
    }

    [Fact]
    public void Ulong_attribute_has_native_width_little_endian_bytes()
    {
        using var scope = new NativeAllocationScope();

        var attribute = scope.Attribute(CK_ATTRIBUTE_TYPE.CKA_MODULUS_BITS, (NativeULong)2048);

        Assert.Equal((NativeULong)sizeof(NativeULong), attribute.ValueLength);
        Assert.Equal((NativeULong)2048, ReadNativeULong(attribute.Value));
    }

    [Fact]
    public void Object_class_attribute_carries_the_enum_value()
    {
        using var scope = new NativeAllocationScope();

        var attribute = scope.Attribute(CK_ATTRIBUTE_TYPE.CKA_CLASS, CK_OBJECT_CLASS.CKO_PRIVATE_KEY);

        Assert.Equal((NativeULong)sizeof(NativeULong), attribute.ValueLength);
        Assert.Equal((NativeULong)CK_OBJECT_CLASS.CKO_PRIVATE_KEY, ReadNativeULong(attribute.Value));
    }

    private static NativeULong ReadNativeULong(IntPtr pointer)
    {
        var buffer = new byte[sizeof(NativeULong)];
        Marshal.Copy(pointer, buffer, 0, buffer.Length);
        return System.Runtime.InteropServices.MemoryMarshal.Read<NativeULong>(buffer);
    }
}
