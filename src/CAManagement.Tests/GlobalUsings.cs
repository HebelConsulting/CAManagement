// Mirrors CAManagement.Pkcs11's platform alias (SPEC decision #4).
#if WINDOWS
global using NativeULong = System.UInt32;
#else
global using NativeULong = System.UInt64;
#endif
