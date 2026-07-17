using System.Runtime.InteropServices;

namespace CAManagement.Pkcs11.DataStructures;

// Unix LP64 natural alignment (SPEC #4). Pack=1 here would drop the trailing
// padding after the CK_ULONG flags and under-size the marshalled buffer.
[StructLayout(LayoutKind.Sequential)]
public struct CK_SLOT_INFO
{
    public InlineArray64 SlotDescription;
    
    public InlineArray32 ManufacturerId;
    
    public CK_SLOT_INFO_FLAGS Flags;
    
    public CK_VERSION HardwareVersion;
    
    public CK_VERSION FirmwareVersion;
}