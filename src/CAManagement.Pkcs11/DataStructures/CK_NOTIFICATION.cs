// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

public enum CK_NOTIFICATION : NativeULong
{
    CKN_SURRENDER = 0,
    CKN_OTP_CHANGED = 1,
}
