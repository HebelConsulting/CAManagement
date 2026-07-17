using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_RSA_PKCS_PSS_PARAMS
{
    public CK_MECHANISM_TYPE HashAlgorithm;

    public CK_RSA_PKCS_MGF_TYPE Mgf;

    public NativeULong SaltLength;
}
