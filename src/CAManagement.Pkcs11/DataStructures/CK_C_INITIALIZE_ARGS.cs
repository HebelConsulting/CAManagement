// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

namespace CAManagement.Pkcs11.DataStructures;

[StructLayout(LayoutKind.Sequential, Pack = Pkcs11Layout.Pack)]
public struct CK_C_INITIALIZE_ARGS
{
    public CK_C_INITIALIZE_ARGS() {}
    
    public IntPtr CreateMutex = IntPtr.Zero;
    
    public IntPtr DestroyMutex = IntPtr.Zero;
    
    public IntPtr LockMutex = IntPtr.Zero;
    
    public IntPtr UnlockMutex = IntPtr.Zero;
    
    public CK_C_INITIALIZE_ARGS_FLAGS Flags = 0;
    
    public IntPtr Reserved = IntPtr.Zero;
}