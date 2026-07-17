// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

public enum CK_NOTIFICATION : NativeULong
{
    CKN_SURRENDER = 0UL,
    CKN_OTP_CHANGED = 1UL,
}
