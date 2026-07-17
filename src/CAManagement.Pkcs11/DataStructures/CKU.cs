// ReSharper disable InconsistentNaming

namespace CAManagement.Pkcs11.DataStructures;

public enum CKU : NativeULong
{
    CKU_SO = 0,
    
    CKU_USER = 1,
    
    CKU_CONTEXT_SPECIFIC = 2,
}