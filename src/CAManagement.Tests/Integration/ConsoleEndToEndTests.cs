using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CAManagement.Tests.Unit;
using CAManagement.X509;

namespace CAManagement.Tests.Integration;

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
            // The Disig SoftHSM2 Windows build is 2.5.0 and lacks CKM_ECDSA_SHA256,
            // so the CA key is RSA there (still exercises the whole lifecycle and
            // the LLP64 ABI); macOS keeps EC coverage.
            var caKeyType = OperatingSystem.IsWindows() ? "rsa" : "ec";
            var initCa = Run(binary, ["init-ca", "--token-label", "e2e-token", "--pin", UserPin, "--label", "e2e-root",
                "--key-type", caKeyType,
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

            var issue = Run(binary, ["issue", "--token-label", "e2e-token", "--pin", UserPin, "--ca-label", "e2e-root",
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
            var genCrl = Run(binary, ["gen-crl", "--token-label", "e2e-token", "--pin", UserPin, "--ca-label", "e2e-root",
                "--ca-cert", "ca.crt", "--out", "ca.crl"], workDir.FullName, environment);
            Assert.True(genCrl.ExitCode == 0, $"gen-crl failed: {genCrl.Output}");

            var crlDer = ReadPem(workDir.FullName, "ca.crl");
            CertificateRevocationListBuilder.Load(crlDer, out BigInteger crlNumber);
            Assert.Equal(BigInteger.One, crlNumber);
            Assert.True(CrlBuilderTests.CrlSignatureIsValid(crlDer, caCertificate),
                "CRL must verify against the CA certificate");
            Assert.Contains(leafCertificate.SerialNumber,
                Convert.ToHexString(crlDer), StringComparison.OrdinalIgnoreCase);

            // --- ocsp-respond: file mode ----------------------------------------
            var opensslAvailable = File.Exists("/usr/bin/openssl");
            if (opensslAvailable)
            {
                var reqGen = Run("/usr/bin/openssl", ["ocsp", "-issuer", "ca.crt", "-cert", "leaf.crt",
                    "-reqout", "ocsp-req.der", "-no_nonce"], workDir.FullName, environment);
                Assert.True(reqGen.ExitCode == 0, $"openssl request generation failed: {reqGen.Output}");

                var respond = Run(binary, ["ocsp-respond", "--token-label", "e2e-token", "--pin", UserPin, "--ca-label", "e2e-root", "--ca-cert", "ca.crt",
                    "--reqin", "ocsp-req.der", "--respout", "ocsp-resp.der"], workDir.FullName, environment);
                Assert.True(respond.ExitCode == 0, $"ocsp-respond failed: {respond.Output}");

                var ocspVerify = Run("/usr/bin/openssl", ["ocsp", "-respin", "ocsp-resp.der",
                    "-issuer", "ca.crt", "-cert", "leaf.crt", "-CAfile", "ca.crt"], workDir.FullName, environment);
                Assert.True(ocspVerify.ExitCode == 0, $"openssl OCSP verification failed: {ocspVerify.Output}");
                Assert.Contains("Response verify OK", ocspVerify.Output);
                Assert.Contains("leaf.crt: revoked", ocspVerify.Output); // revoked above, before gen-crl
            }

            // --- ocsp-respond: HTTP mode ----------------------------------------
            if (opensslAvailable)
            {
                var port = FreeTcpPort();
                using var server = StartBackground(binary, ["ocsp-respond", "--token-label", "e2e-token", "--pin", UserPin, "--ca-label", "e2e-root",
                    "--ca-cert", "ca.crt", "--listen", $"http://127.0.0.1:{port}/", "--max-requests", "1"],
                    workDir.FullName, environment);

                WaitUntilListening(port);

                var httpVerify = Run("/usr/bin/openssl", ["ocsp", "-url", $"http://127.0.0.1:{port}/",
                    "-issuer", "ca.crt", "-cert", "leaf.crt", "-CAfile", "ca.crt", "-no_nonce"],
                    workDir.FullName, environment);
                Assert.True(httpVerify.ExitCode == 0, $"openssl OCSP-over-HTTP failed: {httpVerify.Output}");
                Assert.Contains("Response verify OK", httpVerify.Output);
                Assert.Contains("leaf.crt: revoked", httpVerify.Output);

                Assert.True(server.WaitForExit(30_000), "responder should exit after --max-requests 1");
                Assert.Equal(0, server.ExitCode);
            }

            // --- CA state on the token ------------------------------------------
            // Fresh store (independent of ca-state.json); revoke and gen-crl run in
            // separate processes, so the state provably persists on the token.
            var tokenRevoke = Run(binary, ["revoke", "--serial", leafCertificate.SerialNumber,
                "--reason", "Superseded", "--state", "token", "--ca-label", "e2e-root", "--token-label", "e2e-token", "--pin", UserPin], workDir.FullName, environment);
            Assert.True(tokenRevoke.ExitCode == 0, $"revoke --state token failed: {tokenRevoke.Output}");

            var tokenGenCrl = Run(binary, ["gen-crl", "--token-label", "e2e-token", "--pin", UserPin, "--ca-label", "e2e-root", "--ca-cert", "ca.crt",
                "--state", "token", "--out", "ca-token.crl"], workDir.FullName, environment);
            Assert.True(tokenGenCrl.ExitCode == 0, $"gen-crl --state token failed: {tokenGenCrl.Output}");

            var tokenCrlDer = ReadPem(workDir.FullName, "ca-token.crl");
            CertificateRevocationListBuilder.Load(tokenCrlDer, out BigInteger tokenCrlNumber);
            Assert.Equal(BigInteger.One, tokenCrlNumber); // fresh on-token store, first CRL
            Assert.True(CrlBuilderTests.CrlSignatureIsValid(tokenCrlDer, caCertificate));
            Assert.Contains(leafCertificate.SerialNumber, Convert.ToHexString(tokenCrlDer), StringComparison.OrdinalIgnoreCase);

            // Revoking the same serial again reports it as already recorded — the
            // entry really was read back from the token, not from any file.
            var tokenRevokeAgain = Run(binary, ["revoke", "--serial", leafCertificate.SerialNumber,
                "--reason", "Superseded", "--state", "token", "--ca-label", "e2e-root", "--token-label", "e2e-token", "--pin", UserPin], workDir.FullName, environment);
            Assert.True(tokenRevokeAgain.ExitCode == 0, tokenRevokeAgain.Output);
            Assert.Contains("already revoked", tokenRevokeAgain.Output);

            // --- asn -------------------------------------------------------------
            var asn = Run(binary, ["asn", "ca.crt"], workDir.FullName, environment);
            Assert.True(asn.ExitCode == 0, $"asn failed: {asn.Output}");
            Assert.Contains("Certificate", asn.Output);
            Assert.Contains("serialNumber", asn.Output);

            // --- wrong PIN fails cleanly ----------------------------------------
            var wrongPin = Run(binary, ["gen-crl", "--token-label", "e2e-token", "--pin", "9999", "--ca-label", "e2e-root",
                "--ca-cert", "ca.crt"], workDir.FullName, environment);
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
        // Locate the project by search so repository layout changes don't break us.
        var csproj = Directory.GetFiles(repoRoot, "CAManagement.Cli.csproj", SearchOption.AllDirectories).Single();
        var framework = OperatingSystem.IsWindows() ? "net10.0-windows" : "net10.0";
        var rid = HostRuntimeIdentifier();

        // Build for the host RID so this runs on any OS/arch (the csproj pins
        // osx-arm64 for local dev; -r overrides it). --disable-build-servers:
        // avoid contending with the outer `dotnet test` session's build servers.
        var build = Run("dotnet", ["build", csproj, "-f", framework, "-r", rid,
            "-c", "Debug", "--nologo", "-v", "q", "--disable-build-servers"], repoRoot, []);
        Assert.True(build.ExitCode == 0, $"console build failed: {build.Output}");

        var exeName = OperatingSystem.IsWindows() ? "caconsole.exe" : "caconsole";
        var binary = Path.Combine(Path.GetDirectoryName(csproj)!, "bin", "Debug", framework, rid, exeName);
        Assert.True(File.Exists(binary), $"console binary not found at {binary}");

        return binary;
    }

    private static string HostRuntimeIdentifier()
    {
        var os = OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "osx" : "linux";
        var arch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.Arm64 => "arm64",
            System.Runtime.InteropServices.Architecture.X64 => "x64",
            var other => throw new PlatformNotSupportedException($"Unsupported architecture {other}."),
        };

        return $"{os}-{arch}";
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
            ["NO_COLOR"] = "1",
        };

        if (SoftHsmFixture.WindowsModulePath is { } moduleDir)
        {
            // Let the CLI's bare default module name resolve via PATH.
            environment["PATH"] = $"{Path.GetDirectoryName(moduleDir)};{Environment.GetEnvironmentVariable("PATH")}";
        }

        var init = Run(SoftHsmFixture.SoftHsmUtilPath, ["--init-token", "--free", "--label", "e2e-token",
            "--so-pin", "12345678", "--pin", UserPin], workDir, environment);
        Assert.True(init.ExitCode == 0, $"token init failed: {init.Output}");

        return environment;
    }

    private static int FreeTcpPort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        return port;
    }

    private static void WaitUntilListening(int port)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                client.Connect(System.Net.IPAddress.Loopback, port);
                return;
            }
            catch (System.Net.Sockets.SocketException)
            {
                Thread.Sleep(100);
            }
        }

        throw new TimeoutException($"OCSP responder did not start listening on port {port}.");
    }

    private static Process StartBackground(
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

        var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start '{fileName}'.");

        // Drain pipes in the background so the child never blocks on full buffers.
        process.StandardOutput.ReadToEndAsync();
        process.StandardError.ReadToEndAsync();

        return process;
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

        // Drain both pipes concurrently — sequential ReadToEnd deadlocks when the
        // child fills the other pipe's buffer first.
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(120_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"'{fileName} {string.Join(' ', arguments)}' did not finish within 120s.");
        }

        return (process.ExitCode, stdout.Result + stderr.Result);
    }
}
