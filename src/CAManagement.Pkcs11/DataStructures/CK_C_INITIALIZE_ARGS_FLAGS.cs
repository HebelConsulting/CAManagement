// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

[Flags]
public enum CK_C_INITIALIZE_ARGS_FLAGS : NativeULong
{
    CKF_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001,
    CKF_OS_LOCKING_OK = 0x00000002,
}