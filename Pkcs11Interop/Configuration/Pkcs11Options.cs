using System.Runtime.InteropServices;

namespace Pkcs11Interop.Configuration;

/// <summary>
/// Options for loading and using a PKCS#11 module. Bound from the
/// <c>Pkcs11</c> configuration section (SPEC decision #5).
/// </summary>
public sealed class Pkcs11Options
{
    public const string SectionName = "Pkcs11";

    /// <summary>Path to (or loader name of) the PKCS#11 module. Per-OS default (SPEC #2).</summary>
    public string ModulePath { get; set; } = DefaultModulePath;

    /// <summary>Preferred slot selection: the token label to look up (SPEC #9).</summary>
    public string? TokenLabel { get; set; }

    /// <summary>Explicit slot id, overriding <see cref="TokenLabel"/> when set.</summary>
    public NativeULong? SlotId { get; set; }

    /// <summary>User PIN. Dev-only in config; secret handling is a later concern.</summary>
    public string? UserPin { get; set; }

    /// <summary>Initialize Cryptoki with <c>CKF_OS_LOCKING_OK</c> (SPEC #8).</summary>
    public bool UseOsLocking { get; set; } = true;

    private static string DefaultModulePath => RuntimeInformation.IsOSPlatform(OSPlatform.OSX) switch
    {
        true => RuntimeInformation.OSArchitecture == Architecture.Arm64
            ? "/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so"
            : "/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so",
        false => RuntimeInformation.IsOSPlatform(OSPlatform.Linux) switch
        {
            true => "/usr/lib/softhsm/libsofthsm2.so",
            false => "libsofthsm2.so", // Windows/other: expect an explicit override
        },
    };
}
