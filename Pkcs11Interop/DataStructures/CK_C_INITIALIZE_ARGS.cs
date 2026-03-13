// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

namespace Pkcs11Interop.DataStructures;

[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
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