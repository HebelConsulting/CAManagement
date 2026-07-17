using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_MECHANISM_INFO
{
    public NativeULong MinKeySize;

    public NativeULong MaxKeySize;

    public CK_MECHANISM_INFO_FLAGS Flags;
}
