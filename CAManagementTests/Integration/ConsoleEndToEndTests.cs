using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CAManagementTests.Unit;
using CertificateAuthority;

namespace CAManagementTests.Integration;

/// <summary>
/// Drives the caconsole binary as real child processes through the full CA
/// lifecycle: init-ca → issue (from a CSR) → revoke → gen-crl → asn, against a
/// throwaway SoftHSM token. Child processes receive SOFTHSM2_CONF via their
/// process environment, so the native-getenv issue does not apply here.
/// </summary>
public sealed class ConsoleEndToEndTests
{
    private const string UserPin = "1234";

    [Fact]
    public void Full_ca_lifecycle_through_the_console_binary()
    {
        var repoRoot = FindRepoRoot();
        var binary = BuildConsole(repoRoot);

        var workDir = Directory.CreateTempSubdirectory("caconsole-e2e");
        try
        {
            var environment = ProvisionToken(workDir.FullName);

            // --- init-ca ---------------------------------------------------------
            var initCa = Run(binary, ["init-ca", "--label", "e2e-root",
                "--subject", "C=CH, O=Hebel Consulting, CN=E2E Root CA", "--out", "ca.crt"], workDir.FullName, environment);
            Assert.True(initCa.ExitCode == 0, $"init-ca failed: {initCa.Output}");

            var caDer = ReadPem(workDir.FullName, "ca.crt");
            using var caCertificate = X509CertificateLoader.LoadCertificate(caDer);
            Assert.True(caCertificate.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority);
            Assert.Contains("CN=E2E Root CA", caCertificate.Subject);

            // --- issue from a CSR ------------------------------------------------
            using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var csrDer = new CertificateRequest(new X500DistinguishedName("CN=e2e-leaf.example.test"),
                leafKey, HashAlgorithmName.SHA256).CreateSigningRequest();
            File.WriteAllText(Path.Combine(workDir.FullName, "leaf.csr"), Pem.Encode("CERTIFICATE REQUEST", csrDer));

            var issue = Run(binary, ["issue", "--ca-label", "e2e-root",
                "--ca-cert", "ca.crt", "--csr", "leaf.csr", "--out", "leaf.crt"], workDir.FullName, environment);
            Assert.True(issue.ExitCode == 0, $"issue failed: {issue.Output}");

            using var leafCertificate = X509CertificateLoader.LoadCertificate(ReadPem(workDir.FullName, "leaf.crt"));
            Assert.Contains("CN=e2e-leaf.example.test", leafCertificate.Subject);
            Assert.True(CertificateBuilderTests.ChainValidates(leafCertificate, caCertificate),
                "issued certificate must chain to the CA root");

            // --- revoke ----------------------------------------------------------
            var revoke = Run(binary, ["revoke", "--serial", leafCertificate.SerialNumber,
                "--reason", "KeyCompromise"], workDir.FullName, environment);
            Assert.True(revoke.ExitCode == 0, $"revoke failed: {revoke.Output}");
            Assert.True(File.Exists(Path.Combine(workDir.FullName, "ca-state.json")));

            // --- gen-crl ---------------------------------------------------------
            var genCrl = Run(binary, ["gen-crl", "--ca-label", "e2e-root",
                "--ca-cert", "ca.crt", "--out", "ca.crl"], workDir.FullName, environment);
            Assert.True(genCrl.ExitCode == 0, $"gen-crl failed: {genCrl.Output}");

            var crlDer = ReadPem(workDir.FullName, "ca.crl");
            CertificateRevocationListBuilder.Load(crlDer, out BigInteger crlNumber);
            Assert.Equal(BigInteger.One, crlNumber);
            Assert.True(CrlBuilderTests.CrlSignatureIsValid(crlDer, caCertificate),
                "CRL must verify against the CA certificate");
            Assert.Contains(leafCertificate.SerialNumber,
                Convert.ToHexString(crlDer), StringComparison.OrdinalIgnoreCase);

            // --- asn -------------------------------------------------------------
            var asn = Run(binary, ["asn", "ca.crt"], workDir.FullName, environment);
            Assert.True(asn.ExitCode == 0, $"asn failed: {asn.Output}");
            Assert.Contains("Certificate", asn.Output);
            Assert.Contains("serialNumber", asn.Output);

            // --- wrong PIN fails cleanly ----------------------------------------
            var wrongPin = Run(binary, ["gen-crl", "--ca-label", "e2e-root",
                "--ca-cert", "ca.crt", "--pin", "9999"], workDir.FullName, environment);
            Assert.NotEqual(0, wrongPin.ExitCode);
            Assert.Contains("CKR_PIN_INCORRECT", wrongPin.Output);
        }
        finally
        {
            workDir.Delete(recursive: true);
        }
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CAManagement.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("CAManagement.sln not found above the test directory.");
    }

    private static string BuildConsole(string repoRoot)
    {
        var build = Run("dotnet", ["build", Path.Combine(repoRoot, "CAConsole", "CAConsole.csproj"),
            "-c", "Debug", "--nologo", "-v", "q"], repoRoot, []);
        Assert.True(build.ExitCode == 0, $"console build failed: {build.Output}");

        var binary = Path.Combine(repoRoot, "CAConsole", "bin", "Debug", "net10.0", "osx-arm64", "caconsole");
        Assert.True(File.Exists(binary), $"console binary not found at {binary}");

        return binary;
    }

    private static Dictionary<string, string> ProvisionToken(string workDir)
    {
        var tokenDir = Path.Combine(workDir, "tokens");
        Directory.CreateDirectory(tokenDir);
        var configPath = Path.Combine(workDir, "softhsm2.conf");
        File.WriteAllText(configPath, $"""
            directories.tokendir = {tokenDir}
            objectstore.backend = file
            log.level = ERROR
            """);

        var environment = new Dictionary<string, string>
        {
            ["SOFTHSM2_CONF"] = configPath,
            ["Pkcs11__TokenLabel"] = "e2e-token",
            ["Pkcs11__UserPin"] = UserPin,
            ["NO_COLOR"] = "1",
        };

        var init = Run("softhsm2-util", ["--init-token", "--free", "--label", "e2e-token",
            "--so-pin", "12345678", "--pin", UserPin], workDir, environment);
        Assert.True(init.ExitCode == 0, $"token init failed: {init.Output}");

        return environment;
    }

    private static byte[] ReadPem(string directory, string fileName) =>
        Pem.TryDecodeFirst(File.ReadAllText(Path.Combine(directory, fileName)))!.Value.Der;

    private static (int ExitCode, string Output) Run(
        string fileName, string[] arguments, string workingDirectory, Dictionary<string, string> environment)
    {
        var startInfo = new ProcessStartInfo(fileName)
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        foreach (var (key, value) in environment)
        {
            startInfo.Environment[key] = value;
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start '{fileName}'.");

        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();

        if (!process.WaitForExit(120_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"'{fileName} {string.Join(' ', arguments)}' did not finish within 120s.\n{output}");
        }

        return (process.ExitCode, output);
    }
}
