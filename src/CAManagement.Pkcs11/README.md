# CAManagement.Pkcs11

PKCS#11 v2.40 interop for .NET: loads any PKCS#11 module (SoftHSM2, YubiKey, …)
via `NativeLibrary.Load`, resolves only `C_GetFunctionList` and calls everything
else through the function-list pointers. Sessions, login scopes, key generation,
sign/verify and object management with disciplined native-memory ownership.

Part of [CAManagement](https://github.com/HebelConsulting/CAManagement).
