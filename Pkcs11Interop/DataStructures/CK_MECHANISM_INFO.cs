using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_MECHANISM_INFO
{
    public NativeULong MinKeySize;

    public NativeULong MaxKeySize;

    public CK_MECHANISM_INFO_FLAGS Flags;
}
