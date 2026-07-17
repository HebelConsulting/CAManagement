using System.Diagnostics;
using System.Text;
using CertificateAuthority;
using CertificateAuthority.Analysis;

namespace CAManagementTests.Unit;

public sealed class SshKeyAnalysisTests
{
    private static readonly bool SshKeygenAvailable = File.Exists("/usr/bin/ssh-keygen");

    [Fact]
    public void Openssh_public_key_gets_a_conversion_hint()
    {
        var line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE user@host\n";

        var exception = Assert.Throws<FormatException>(() => Asn1Analyzer.Analyze(Encoding.UTF8.GetBytes(line)));

        Assert.Contains("SSH wire format", exception.Message);
        Assert.Contains("ssh-keygen -e -m PKCS8", exception.Message);
        Assert.Contains("Ed25519", exception.Message); // honest about the unconvertible case
    }

    [Fact]
    public void Openssh_private_key_gets_a_conversion_hint()
    {
        var pem = Pem.Encode("OPENSSH PRIVATE KEY", "openssh-key-v1\0fake-payload"u8.ToArray());

        var exception = Assert.Throws<FormatException>(() => Asn1Analyzer.Analyze(pem));

        Assert.Contains("openssh-key-v1", exception.Message);
        Assert.Contains("ssh-keygen -p", exception.Message);
    }

    [Fact]
    public void Synthesized_ed25519_spki_is_detected_and_named()
    {
        // SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (32 zero bytes) }
        byte[] der =
        [
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
            0x03, 0x21, 0x00, .. new byte[32],
        ];

        var document = Asn1Analyzer.Analyze(der);

        Assert.Equal(DocumentKind.SubjectPublicKeyInfo, document.Kind);
        Assert.Contains("Ed25519", document.Root.Children[0].Children[0].Value);
    }

    [Fact]
    public void Sshkeygen_converted_keys_analyze_as_asn1()
    {
        // ECDSA on purpose: OpenSSH cannot export Ed25519 keys to any ASN.1
        // format (-e/-p -m PKCS8 fail or silently keep openssh-key-v1).
        if (!SshKeygenAvailable)
        {
            return;
        }

        var workDir = Directory.CreateTempSubdirectory("ssh-analyze");
        try
        {
            var keyPath = Path.Combine(workDir.FullName, "id_ecdsa");
            Run("/usr/bin/ssh-keygen", ["-t", "ecdsa", "-N", "", "-q", "-f", keyPath]);

            // Public key: ssh-keygen -e -m PKCS8 prints a PUBLIC KEY PEM to stdout.
            var publicPem = Run("/usr/bin/ssh-keygen", ["-e", "-m", "PKCS8", "-f", $"{keyPath}.pub"]);
            var publicDocument = Asn1Analyzer.Analyze(publicPem);
            Assert.Equal(DocumentKind.SubjectPublicKeyInfo, publicDocument.Kind);

            // Private key: ssh-keygen -p -m PKCS8 converts the file in place.
            Run("/usr/bin/ssh-keygen", ["-p", "-N", "", "-m", "PKCS8", "-q", "-f", keyPath]);
            var privateDocument = Asn1Analyzer.Analyze(File.ReadAllBytes(keyPath));
            Assert.Equal(DocumentKind.Pkcs8PrivateKey, privateDocument.Kind);
        }
        finally
        {
            workDir.Delete(recursive: true);
        }
    }

    private static string Run(string fileName, string[] arguments)
    {
        var startInfo = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"{fileName} {string.Join(' ', arguments)} failed: {stderr.Result}");

        return stdout.Result;
    }
}
