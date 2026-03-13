using NativeULong = System.UInt64;

// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

[Flags]
public enum CK_C_INITIALIZE_ARGS_FLAGS : NativeULong
{
    CKF_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001UL,
    CKF_OS_LOCKING_OK = 0x00000002UL,
}