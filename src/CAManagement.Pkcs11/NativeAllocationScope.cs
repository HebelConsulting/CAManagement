using System.Runtime.InteropServices;
using System.Text;
using CAManagement.Pkcs11.DataStructures;

namespace CAManagement.Pkcs11;

/// <summary>
/// Owns the unmanaged memory backing PKCS#11 attribute templates and mechanism
/// parameters for the duration of a single operation. Disposing frees every
/// allocation (SPEC decision #7 — fixes the previous leak).
/// </summary>
public sealed class NativeAllocationScope : IDisposable
{
    private readonly List<IntPtr> _allocations = [];

    public IntPtr Allocate(ReadOnlySpan<byte> content)
    {
        var size = content.Length;
        var memory = Marshal.AllocHGlobal(size == 0 ? 1 : size);
        _allocations.Add(memory);

        if (size > 0)
        {
            unsafe { content.CopyTo(new Span<byte>((void*)memory, size)); }
        }

        return memory;
    }

    public CK_ATTRIBUTE Attribute(CK_ATTRIBUTE_TYPE type, ReadOnlySpan<byte> value) => new()
    {
        Type = type,
        Value = Allocate(value),
        ValueLength = (NativeULong)value.Length,
    };

    // CK_BBOOL is a single byte.
    public CK_ATTRIBUTE Attribute(CK_ATTRIBUTE_TYPE type, bool value) => Attribute(type, [(byte)(value ? 1 : 0)]);

    // CK_ULONG-valued attributes (native endianness matches the token in-process).
    public CK_ATTRIBUTE Attribute(CK_ATTRIBUTE_TYPE type, NativeULong value) => Attribute(type, BitConverter.GetBytes(value));

    public CK_ATTRIBUTE Attribute(CK_ATTRIBUTE_TYPE type, CK_OBJECT_CLASS value) => Attribute(type, (NativeULong)value);

    public CK_ATTRIBUTE Attribute(CK_ATTRIBUTE_TYPE type, CK_KEY_TYPE value) => Attribute(type, (NativeULong)value);

    public CK_ATTRIBUTE Attribute(CK_ATTRIBUTE_TYPE type, CK_CERTIFICATE_TYPE value) => Attribute(type, (NativeULong)value);

    public CK_ATTRIBUTE Attribute(CK_ATTRIBUTE_TYPE type, string value) => Attribute(type, Encoding.UTF8.GetBytes(value));

    public void Dispose()
    {
        foreach (var allocation in _allocations)
        {
            Marshal.FreeHGlobal(allocation);
        }

        _allocations.Clear();
    }
}
