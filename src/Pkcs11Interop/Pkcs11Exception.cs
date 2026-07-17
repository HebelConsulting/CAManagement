using Pkcs11Interop.DataStructures;

namespace Pkcs11Interop;

/// <summary>
/// Thrown when a PKCS#11 call returns a value other than <see cref="CK_RV.CKR_OK"/>
/// (SPEC decision #6).
/// </summary>
public class Pkcs11Exception : Exception
{
    public CK_RV ReturnValue { get; }

    public string Operation { get; }

    public Pkcs11Exception(CK_RV returnValue, string operation)
        : base($"PKCS#11 call '{operation}' failed with {returnValue} (0x{(NativeULong)returnValue:X8}).")
    {
        ReturnValue = returnValue;
        Operation = operation;
    }
}
