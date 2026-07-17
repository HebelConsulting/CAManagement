using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_ECDH1_DERIVE_PARAMS
{
    public CK_EC_KDF_TYPE Kdf;

    public NativeULong SharedDataLength;

    public IntPtr SharedData;

    public NativeULong PublicDataLength;

    public IntPtr PublicData;
}
