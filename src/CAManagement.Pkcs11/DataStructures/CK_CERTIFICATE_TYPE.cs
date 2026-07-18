// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

public enum CK_CERTIFICATE_TYPE : NativeULong
{
    CKC_X_509 = 0x00000000,
    CKC_X_509_ATTR_CERT = 0x00000001,
    CKC_WTLS = 0x00000002,
    CKC_VENDOR_DEFINED = 0x80000000,
}
