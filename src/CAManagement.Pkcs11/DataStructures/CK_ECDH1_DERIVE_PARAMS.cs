using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

[StructLayout(LayoutKind.Sequential, Pack = Pkcs11Layout.Pack)]
public struct CK_ECDH1_DERIVE_PARAMS
{
    public CK_EC_KDF_TYPE Kdf;

    public NativeULong SharedDataLength;

    public IntPtr SharedData;

    public NativeULong PublicDataLength;

    public IntPtr PublicData;
}
