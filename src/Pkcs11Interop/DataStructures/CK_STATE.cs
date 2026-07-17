// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

public enum CK_STATE : NativeULong
{
    CKS_RO_PUBLIC_SESSION = 0UL,
    CKS_RO_USER_FUNCTIONS = 1UL,
    CKS_RW_PUBLIC_SESSION = 2UL,
    CKS_RW_USER_FUNCTIONS = 3UL,
    CKS_RW_SO_FUNCTIONS = 4UL,
}
