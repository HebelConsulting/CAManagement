// Mirrors CAManagement.Pkcs11's platform alias (SPEC decision #4): CK_ULONG is
// 8 bytes on Unix LP64 (net10.0), 4 bytes on Windows LLP64 (net10.0-windows).
#if WINDOWS
global using NativeULong = System.UInt32;
#else
global using NativeULong = System.UInt64;
#endif
