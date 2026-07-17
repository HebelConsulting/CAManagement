using System.Runtime.InteropServices;

namespace CAManagement.Pkcs11.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_ATTRIBUTE
{
    public CK_ATTRIBUTE_TYPE Type;
    
    public IntPtr Value;
    
    public NativeULong ValueLength;
}