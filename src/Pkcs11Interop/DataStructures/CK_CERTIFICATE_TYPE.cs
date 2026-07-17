// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

public enum CK_CERTIFICATE_TYPE : NativeULong
{
    CKC_X_509 = 0x00000000UL,
    CKC_X_509_ATTR_CERT = 0x00000001UL,
    CKC_WTLS = 0x00000002UL,
    CKC_VENDOR_DEFINED = 0x80000000UL,
}
