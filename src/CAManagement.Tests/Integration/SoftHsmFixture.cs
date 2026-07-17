using System.Diagnostics;
using System.Runtime.InteropServices;
using CAManagement.Pkcs11.Configuration;

namespace CAManagement.Tests.Integration;

/// <summary>
/// Provisions an isolated, throwaway SoftHSM2 token for integration tests
/// (SPEC decision #8). Writes a private <c>softhsm2.conf</c>, points
/// <c>SOFTHSM2_CONF</c> at it, initializes a fresh token, and tears the whole
/// directory down afterwards — the developer's real tokens are never touched.
/// </summary>
public sealed class SoftHsmFixture : IDisposable
{
    public const string TokenLabel = "ca-test";
    public const string SoPin = "12345678";
    public const string UserPin = "1234";

    private readonly string _rootDirectory;

    public SoftHsmFixture()
    {
        _rootDirectory = Path.Combine(Path.GetTempPath(), $"softhsm-camgmt-{Guid.NewGuid():N}");
        var tokenDirectory = Path.Combine(_rootDirectory, "tokens");
        Directory.CreateDirectory(tokenDirectory);

        var configPath = Path.Combine(_rootDirectory, "softhsm2.conf");
        File.WriteAllText(configPath, $"""
            directories.tokendir = {tokenDirectory}
            objectstore.backend = file
            log.level = ERROR
            """);

        // SoftHSM reads SOFTHSM2_CONF via native getenv() at C_Initialize. On macOS
        // Environment.SetEnvironmentVariable does NOT reach native getenv, so set it
        // through libc setenv as well; do this before any module load.
        Environment.SetEnvironmentVariable("SOFTHSM2_CONF", configPath);
        setenv("SOFTHSM2_CONF", configPath, overwrite: 1);

        RunSoftHsmUtil($"--init-token --free --label {TokenLabel} --so-pin {SoPin} --pin {UserPin}", configPath);
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int setenv(string name, string value, int overwrite);

    public Pkcs11Options CreateOptions() => new()
    {
        TokenLabel = TokenLabel,
        UserPin = UserPin,
    };

    private static void RunSoftHsmUtil(string arguments, string configPath)
    {
        var startInfo = new ProcessStartInfo("softhsm2-util", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.Environment["SOFTHSM2_CONF"] = configPath;

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start 'softhsm2-util'. Is SoftHSM2 installed?");

        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"softhsm2-util {arguments} failed (exit {process.ExitCode}).\n{stdout.Result}\n{stderr.Result}");
        }
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_rootDirectory, recursive: true);
        }
        catch
        {
            // Best-effort cleanup of the throwaway token directory.
        }
    }
}

[CollectionDefinition(Name)]
public sealed class SoftHsmCollection : ICollectionFixture<SoftHsmFixture>
{
    public const string Name = "SoftHSM";
}
