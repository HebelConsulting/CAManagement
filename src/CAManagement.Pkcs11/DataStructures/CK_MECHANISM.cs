using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

[StructLayout(LayoutKind.Sequential, Pack = Pkcs11Layout.Pack)]
public struct CK_MECHANISM
{
    public CK_MECHANISM_TYPE Mechanism;

    public IntPtr Parameter;
    
    public NativeULong ParameterLength;
}