using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_INFO
{
    public CK_VERSION CryptokiVersion;

    public InlineArray32 ManufacturerId;

    public NativeULong Flags; // must be zero per spec

    public InlineArray32 LibraryDescription;

    public CK_VERSION LibraryVersion;
}
