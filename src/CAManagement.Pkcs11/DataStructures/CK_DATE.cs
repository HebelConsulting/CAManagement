using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace CAManagement.Pkcs11.DataStructures;

/// <summary>ASCII date fields, e.g. year "2026", month "07", day "17".</summary>
[StructLayout(LayoutKind.Sequential, Pack = Pkcs11Layout.Pack)]
public struct CK_DATE
{
    public InlineArray4 Year;

    public InlineArray2 Month;

    public InlineArray2 Day;
}
