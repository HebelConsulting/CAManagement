using NativeULong = System.UInt64;

// ReSharper disable InconsistentNaming

namespace Pkcs11Interop.DataStructures;

[Flags]
public enum CK_TOKEN_INFO_FLAGS : NativeULong
{
    CKF_RNG             = 0x00000001UL,
    CKF_WRITE_PROTECTED = 0x00000002UL,
}