using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming

namespace Pkcs11Interop.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_TOKEN_INFO
{
    public InlineArray32 Label;
    
    public InlineArray32 ManufacturerId;

    public InlineArray16 Model;

    public InlineArray16 SerialNumber;
    
    public CK_TOKEN_INFO_FLAGS Flags;
    
    public NativeULong MaxSessionCount;
    
    public NativeULong SessionCount;
    
    public NativeULong MaxRwSessionCount;
    
    public NativeULong RwSessionCount;
    
    public NativeULong MaxPinLength;
    
    public NativeULong MinPinLength;
    
    public NativeULong TotalPublicMemory;
    
    public NativeULong FreePublicMemory;
    
    public NativeULong TotalPrivateMemory;
    
    public NativeULong FreePrivateMemory;
    
    public CK_VERSION HardwareVersion;
    
    public CK_VERSION FirmwareVersion;
    
    public InlineArray16 UtcTime;
}