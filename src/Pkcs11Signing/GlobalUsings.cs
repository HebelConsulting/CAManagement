// Mirrors Pkcs11Interop's platform alias (SPEC decision #4): CK_ULONG is 8 bytes
// on Unix LP64, 4 bytes on Windows LLP64. Switch both together when porting.
global using NativeULong = System.UInt64;
