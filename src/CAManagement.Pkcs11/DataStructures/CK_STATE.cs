// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

public enum CK_STATE : NativeULong
{
    CKS_RO_PUBLIC_SESSION = 0,
    CKS_RO_USER_FUNCTIONS = 1,
    CKS_RW_PUBLIC_SESSION = 2,
    CKS_RW_USER_FUNCTIONS = 3,
    CKS_RW_SO_FUNCTIONS = 4,
}
