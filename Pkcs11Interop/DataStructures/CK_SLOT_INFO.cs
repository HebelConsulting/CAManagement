using System.Runtime.InteropServices;

namespace Pkcs11Interop.DataStructures;

[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
public struct CK_SLOT_INFO
{
    public InlineArray64 SlotDescription;
    
    public InlineArray32 ManufacturerId;
    
    public CK_SLOT_INFO_FLAGS Flags;
    
    public CK_VERSION HardwareVersion;
    
    public CK_VERSION FirmwareVersion;
}