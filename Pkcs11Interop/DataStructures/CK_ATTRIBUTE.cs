using System.Runtime.InteropServices;
using NativeULong = System.UInt64;

namespace Pkcs11Interop.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_ATTRIBUTE
{
    public CK_ATTRIBUTE_TYPE Type;
    
    public IntPtr Value;
    
    public NativeULong ValueLength;
}