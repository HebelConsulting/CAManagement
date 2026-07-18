using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

[StructLayout(LayoutKind.Sequential, Pack = Pkcs11Layout.Pack)]
public struct CK_SESSION_INFO
{
    public NativeULong SlotId;

    public CK_STATE State;

    public CK_SESSION_INFO_FLAGS Flags;

    public NativeULong DeviceError;
}
