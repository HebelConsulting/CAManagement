// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

namespace CAManagement.Pkcs11.DataStructures;

[StructLayout(LayoutKind.Sequential, Pack = Pkcs11Layout.Pack)]
public struct CK_VERSION
{
    public byte Major;
    
    public byte Minor;

    public override string ToString()
    {
        if (Minor == 0x00)
        {
            return $"{Major}.{Minor}";
        }
        else if (Minor <= 0x63)
        {
            return $"{Major}.{Minor:D2}";
        }
        else
        {
            return "Invalid version";
        }
    }
}