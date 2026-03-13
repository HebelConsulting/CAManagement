using System.Runtime.InteropServices;
using NativeULong = System.UInt64;

// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_MECHANISM
{
    public CK_MECHANISM_TYPE Mechanism;

    public IntPtr Parameter;
    
    public NativeULong ParameterLength;
}