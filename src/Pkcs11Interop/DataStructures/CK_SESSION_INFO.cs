using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_SESSION_INFO
{
    public NativeULong SlotId;

    public CK_STATE State;

    public CK_SESSION_INFO_FLAGS Flags;

    public NativeULong DeviceError;
}
