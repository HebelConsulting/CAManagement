// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

[Flags]
public enum CK_SESSION_INFO_FLAGS : NativeULong
{
    CKF_RW_SESSION = 0x00000002UL,
    CKF_SERIAL_SESSION = 0x00000004UL,
}
