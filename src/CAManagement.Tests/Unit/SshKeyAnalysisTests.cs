using System.Diagnostics;
using CAManagement.X509.Analysis;

namespace CAManagement.Tests.Unit;

public sealed class SshKeyAnalysisTests : IDisposable
{
    private static readonly bool SshKeygenAvailable = File.Exists("/usr/bin/ssh-keygen");

    private readonly DirectoryInfo _workDir = Directory.CreateTempSubdirectory("ssh-analyze");

    public void Dispose() => _workDir.Delete(recursive: true);

    private string Keygen(string type, string passphrase = "", string comment = "test@analyzer")
    {
        var keyPath = Path.Combine(_workDir.FullName, $"id_{type}_{Guid.NewGuid():N}");
        Run("/usr/bin/ssh-keygen", ["-t", type, "-N", passphrase, "-C", comment, "-q", "-f", keyPath]);

        return keyPath;
    }

    private static IEnumerable<Asn1Node> Flatten(Asn1Node node)
    {
        yield return node;
        foreach (var descendant in node.Children.SelectMany(Flatten))
        {
            yield return descendant;
        }
    }

    [Fact]
    public void Decodes_an_ed25519_public_key_line()
    {
        if (!SshKeygenAvailable)
        {
            return;
        }

        var document = Asn1Analyzer.Analyze(File.ReadAllBytes($"{Keygen("ed25519")}.pub"));

        Assert.Equal(DocumentKind.SshPublicKey, document.Kind);
        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n is { Name: "key type", Value: "\"ssh-ed25519\"" });
        Assert.Contains(nodes, n => n is { Name: "public key", Length: 36 }); // 4-byte length + 32 key bytes
        Assert.Contains(nodes, n => n is { Name: "comment", Value: "\"test@analyzer\"" });
    }

    [Fact]
    public void Decodes_an_rsa_public_key_line_with_mpints()
    {
        if (!SshKeygenAvailable)
        {
            return;
        }

        var document = Asn1Analyzer.Analyze(File.ReadAllBytes($"{Keygen("rsa")}.pub"));

        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n is { Name: "e", TagName: "mpint", Value: "65537" });
        Assert.Contains(nodes, n => n is { Name: "n", TagName: "mpint" });
    }

    [Fact]
    public void Decodes_an_unencrypted_ed25519_private_key()
    {
        if (!SshKeygenAvailable)
        {
            return;
        }

        var document = Asn1Analyzer.Analyze(File.ReadAllBytes(Keygen("ed25519")));

        Assert.Equal(DocumentKind.OpenSshPrivateKey, document.Kind);
        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n is { Name: "ciphername", Value: "\"none\"" });
        Assert.Contains(nodes, n => n is { Name: "publickey" }); // embedded public blob…
        Assert.Contains(nodes, n => n is { Name: "key type", Value: "\"ssh-ed25519\"" }); // …parsed inside
        Assert.Contains(nodes, n => n is { Name: "private key" } && n.Explanation!.Contains("SECRET"));
        Assert.Contains(nodes, n => n is { Name: "comment", Value: "\"test@analyzer\"" });
        // "test@analyzer" makes the section land exactly on the 8-byte block
        // boundary — no padding. A one-char comment forces padding bytes.
        var padded = Asn1Analyzer.Analyze(File.ReadAllBytes(Keygen("ed25519", comment: "x")));
        Assert.Contains(Flatten(padded.Root), n => n.Name == "padding");
    }

    [Fact]
    public void Encrypted_private_key_shows_kdf_parameters_but_keeps_secrets_opaque()
    {
        if (!SshKeygenAvailable)
        {
            return;
        }

        var document = Asn1Analyzer.Analyze(File.ReadAllBytes(Keygen("ed25519", passphrase: "test-passphrase")));

        var nodes = Flatten(document.Root).ToList();
        Assert.Contains(nodes, n => n is { Name: "ciphername" } && n.Value!.Contains("aes256"));
        Assert.Contains(nodes, n => n is { Name: "kdfname", Value: "\"bcrypt\"" });
        Assert.Contains(nodes, n => n is { Name: "salt" });
        Assert.Contains(nodes, n => n is { Name: "rounds" });
        var privateSection = nodes.Single(n => n.Name == "private section");
        Assert.Contains("SECRET", privateSection.Explanation!);
        Assert.Empty(privateSection.Children); // no decode without the passphrase
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

        var keyPath = Keygen("ecdsa");

        // Public key: ssh-keygen -e -m PKCS8 prints a PUBLIC KEY PEM to stdout.
        var publicPem = Run("/usr/bin/ssh-keygen", ["-e", "-m", "PKCS8", "-f", $"{keyPath}.pub"]);
        Assert.Equal(DocumentKind.SubjectPublicKeyInfo, Asn1Analyzer.Analyze(publicPem).Kind);

        // Private key: ssh-keygen -p -m PKCS8 converts the file in place.
        Run("/usr/bin/ssh-keygen", ["-p", "-N", "", "-m", "PKCS8", "-q", "-f", keyPath]);
        Assert.Equal(DocumentKind.Pkcs8PrivateKey, Asn1Analyzer.Analyze(File.ReadAllBytes(keyPath)).Kind);
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
