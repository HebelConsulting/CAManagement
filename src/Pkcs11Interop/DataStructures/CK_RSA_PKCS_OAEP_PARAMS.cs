using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_RSA_PKCS_OAEP_PARAMS
{
    public CK_MECHANISM_TYPE HashAlgorithm;

    public CK_RSA_PKCS_MGF_TYPE Mgf;

    public CK_RSA_PKCS_OAEP_SOURCE_TYPE Source;

    public IntPtr SourceData;

    public NativeULong SourceDataLength;
}
