// ReSharper disable InconsistentNaming

namespace Pkcs11Interop.DataStructures;

public enum CKU : uint
{
    CKU_SO = 0,
    
    CKU_USER = 1,
    
    CKU_CONTEXT_SPECIFIC = 2,
}