using System.Buffers.Binary;
using System.Text;

namespace CAManagement.X509.Analysis;

/// <summary>
/// Decodes OpenSSH key material — not ASN.1, but the analyzer renders it with
/// the same tree model: the RFC 4253 public-key wire format ("ssh-ed25519
/// AAAA… comment") and the proprietary 'openssh-key-v1' private container.
/// Best-effort like the DER analyzer: unexpected trailing content becomes an
/// opaque node instead of an error. Encrypted private sections stay opaque;
/// their KDF parameters (bcrypt salt/rounds) are surfaced instead.
/// </summary>
public static class SshKeyAnalyzer
{
    public static AnalyzedDocument AnalyzePublicKeyLine(string line)
    {
        var parts = line.Trim().Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            throw new FormatException("Malformed OpenSSH public key line (expected '<type> <base64> [comment]').");
        }

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(parts[1]);
        }
        catch (FormatException)
        {
            throw new FormatException("The OpenSSH public key blob is not valid base64.");
        }

        var root = new Asn1Node
        {
            TagName = "openssh-public-key",
            Offset = 0,
            Length = blob.Length,
            Name = "SshPublicKey",
            Explanation = "OpenSSH public key (RFC 4253 wire format; offsets refer to the decoded blob)",
        };

        var reader = new SshWireReader(blob, baseOffset: 0);
        AppendPublicKeyFields(root, reader);
        reader.AppendRemainderIfAny(root);

        if (parts.Length == 3)
        {
            root.Children.Add(new Asn1Node
            {
                TagName = "comment",
                Offset = blob.Length,
                Length = 0,
                Value = $"\"{parts[2]}\"",
                Name = "comment",
                Explanation = "Free-text comment (outside the encoded blob)",
            });
        }

        return new AnalyzedDocument(DocumentKind.SshPublicKey, root);
    }

    public static AnalyzedDocument AnalyzeOpenSshPrivateKey(byte[] data)
    {
        var root = new Asn1Node
        {
            TagName = "openssh-key-v1",
            Offset = 0,
            Length = data.Length,
            Name = "OpenSshPrivateKey",
            Explanation = "OpenSSH private key container (PROTOCOL.key) — contains secret key material",
        };

        var magic = "openssh-key-v1\0"u8;
        if (data.Length < magic.Length || !data.AsSpan(0, magic.Length).SequenceEqual(magic))
        {
            throw new FormatException("Missing 'openssh-key-v1' magic — not an OpenSSH private key.");
        }

        root.Children.Add(new Asn1Node
        {
            TagName = "magic",
            Offset = 0,
            Length = magic.Length,
            Value = "\"openssh-key-v1\\0\"",
            Name = "magic",
            Explanation = "Format identifier",
        });

        try
        {
            var reader = new SshWireReader(data[magic.Length..], baseOffset: magic.Length);

            var cipherName = reader.ReadString(root, "ciphername", "Cipher protecting the private section ('none' = unencrypted)");
            reader.ReadString(root, "kdfname", "Key derivation function for the passphrase ('none' = unencrypted)");

            var kdfOptions = reader.ReadStringRaw(out var kdfNode);
            kdfNode.Name = "kdfoptions";
            kdfNode.Explanation = "KDF parameters (empty when unencrypted)";
            root.Children.Add(kdfNode);
            AppendBcryptOptions(kdfNode);

            var keyCount = reader.ReadUInt32(root, "number of keys", "Keys in this container");

            for (var i = 0; i < keyCount; i++)
            {
                var publicBlob = reader.ReadStringRaw(out var publicNode);
                publicNode.Name = "publickey";
                publicNode.Explanation = "Embedded public key (RFC 4253 wire format)";
                root.Children.Add(publicNode);

                var publicReader = new SshWireReader(publicBlob, publicNode.Offset + 4);
                AppendPublicKeyFields(publicNode, publicReader);
            }

            var privateSection = reader.ReadStringRaw(out var privateNode);
            privateNode.Name = "private section";
            root.Children.Add(privateNode);

            if (cipherName == "none")
            {
                privateNode.Explanation = "Unencrypted private key list";
                AppendPlaintextPrivateSection(privateNode, privateSection, privateNode.Offset + 4);
            }
            else
            {
                privateNode.Explanation = $"SECRET — encrypted with {cipherName}; needs the passphrase to decode";
            }

            reader.AppendRemainderIfAny(root);
        }
        catch (FormatException)
        {
            AppendOpaque(root, "unparsed remainder", "Content that did not parse as openssh-key-v1");
        }

        return new AnalyzedDocument(DocumentKind.OpenSshPrivateKey, root);
    }

    // --- field parsers --------------------------------------------------------

    private static void AppendPublicKeyFields(Asn1Node parent, SshWireReader reader)
    {
        var keyType = reader.ReadString(parent, "key type", "Algorithm identifier");

        switch (keyType)
        {
            case "ssh-rsa":
                reader.ReadMpint(parent, "e", "RSA public exponent");
                reader.ReadMpint(parent, "n", "RSA modulus");
                break;
            case "ssh-ed25519":
                reader.ReadString(parent, "public key", "32-byte Ed25519 public key", quoteText: false);
                break;
            case var ecdsa when ecdsa.StartsWith("ecdsa-sha2-", StringComparison.Ordinal):
                reader.ReadString(parent, "curve", "Named curve");
                reader.ReadString(parent, "public point", "Uncompressed EC point (0x04 || X || Y)", quoteText: false);
                break;
            case "ssh-dss":
                reader.ReadMpint(parent, "p", "DSA prime");
                reader.ReadMpint(parent, "q", "DSA subprime");
                reader.ReadMpint(parent, "g", "DSA generator");
                reader.ReadMpint(parent, "y", "DSA public key");
                break;
        }
    }

    private static void AppendPlaintextPrivateSection(Asn1Node parent, byte[] section, int baseOffset)
    {
        var reader = new SshWireReader(section, baseOffset);

        var check1 = reader.ReadUInt32(parent, "check1", "Random check value");
        var check2 = reader.ReadUInt32(parent, "check2",
            check1 is { } c1 && reader.LastUInt32 == c1 ? "Matches check1 — decryption/parse is consistent" : "Must equal check1");

        var keyType = reader.ReadString(parent, "key type", "Algorithm identifier (repeated in the private list)");

        switch (keyType)
        {
            case "ssh-ed25519":
                reader.ReadString(parent, "public key", "32-byte Ed25519 public key", quoteText: false);
                reader.ReadString(parent, "private key", "SECRET — 64 bytes: seed || public key", quoteText: false);
                break;
            case "ssh-rsa":
                reader.ReadMpint(parent, "n", "RSA modulus");
                reader.ReadMpint(parent, "e", "RSA public exponent");
                reader.ReadMpint(parent, "d", "SECRET — RSA private exponent");
                reader.ReadMpint(parent, "iqmp", "SECRET — q^-1 mod p");
                reader.ReadMpint(parent, "p", "SECRET — prime factor");
                reader.ReadMpint(parent, "q", "SECRET — prime factor");
                break;
            case var ecdsa when ecdsa.StartsWith("ecdsa-sha2-", StringComparison.Ordinal):
                reader.ReadString(parent, "curve", "Named curve");
                reader.ReadString(parent, "public point", "Uncompressed EC point", quoteText: false);
                reader.ReadMpint(parent, "d", "SECRET — EC private scalar");
                break;
            default:
                AppendOpaque(parent, "key material", "Type-specific key material (unrecognized algorithm)");
                return;
        }

        reader.ReadString(parent, "comment", "Key comment");
        reader.AppendRemainderIfAny(parent, "padding", "Deterministic padding (1, 2, 3, …)");
    }

    private static void AppendBcryptOptions(Asn1Node kdfOptionsNode)
    {
        // bcrypt kdfoptions: string salt, uint32 rounds — nested wire format.
        if (kdfOptionsNode.Length <= 4)
        {
            return;
        }

        try
        {
            var reader = new SshWireReader(kdfOptionsNode.RawContent!, kdfOptionsNode.Offset + 4);
            reader.ReadString(kdfOptionsNode, "salt", "bcrypt KDF salt", quoteText: false);
            reader.ReadUInt32(kdfOptionsNode, "rounds", "bcrypt rounds (higher = slower brute force)");
        }
        catch (FormatException)
        {
            // not bcrypt-shaped — leave the raw node as is
        }
    }

    private static void AppendOpaque(Asn1Node parent, string name, string explanation) =>
        parent.Children.Add(new Asn1Node
        {
            TagName = "bytes",
            Offset = parent.Offset,
            Length = 0,
            Name = name,
            Explanation = explanation,
        });

    // --- wire reader ----------------------------------------------------------

    private sealed class SshWireReader(byte[] data, int baseOffset)
    {
        private int _position;

        public uint? LastUInt32 { get; private set; }

        public string ReadString(Asn1Node parent, string name, string explanation, bool quoteText = true)
        {
            var bytes = ReadStringRaw(out var node);
            node.Name = name;
            node.Explanation = explanation;
            parent.Children.Add(node);

            return quoteText && IsPrintableAscii(bytes) ? Encoding.ASCII.GetString(bytes) : string.Empty;
        }

        public byte[] ReadStringRaw(out Asn1Node node)
        {
            var (content, offset, length) = ReadLengthPrefixed();
            node = new Asn1Node
            {
                TagName = "string",
                Offset = offset,
                Length = length,
                Value = RenderBytes(content),
                RawContent = content,
            };

            return content;
        }

        private (byte[] Content, int Offset, int Length) ReadLengthPrefixed()
        {
            if (_position + 4 > data.Length)
            {
                throw new FormatException("Truncated SSH wire string length.");
            }

            var length = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(_position));
            if (_position + 4 + length > data.Length)
            {
                throw new FormatException("SSH wire string exceeds the buffer.");
            }

            var content = data.AsSpan(_position + 4, (int)length).ToArray();
            var offset = baseOffset + _position;
            _position += (int)(4 + length);

            return (content, offset, (int)(4 + length));
        }

        public uint? ReadUInt32(Asn1Node parent, string name, string explanation)
        {
            if (_position + 4 > data.Length)
            {
                throw new FormatException("Truncated SSH wire uint32.");
            }

            var value = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(_position));
            parent.Children.Add(new Asn1Node
            {
                TagName = "uint32",
                Offset = baseOffset + _position,
                Length = 4,
                Value = value.ToString(),
                Name = name,
                Explanation = explanation,
            });

            _position += 4;
            LastUInt32 = value;

            return value;
        }

        public void ReadMpint(Asn1Node parent, string name, string explanation)
        {
            var (bytes, offset, length) = ReadLengthPrefixed();
            parent.Children.Add(new Asn1Node
            {
                TagName = "mpint",
                Offset = offset,
                Length = length,
                Value = bytes.Length <= 8
                    ? new System.Numerics.BigInteger(bytes, isUnsigned: false, isBigEndian: true).ToString()
                    : RenderBytes(bytes),
                Name = name,
                Explanation = explanation,
            });
        }

        public void AppendRemainderIfAny(Asn1Node parent, string name = "trailing bytes", string explanation = "Unexpected trailing content")
        {
            if (_position >= data.Length)
            {
                return;
            }

            parent.Children.Add(new Asn1Node
            {
                TagName = "bytes",
                Offset = baseOffset + _position,
                Length = data.Length - _position,
                Value = RenderBytes(data[_position..]),
                Name = name,
                Explanation = explanation,
            });
            _position = data.Length;
        }

        private static string RenderBytes(byte[] bytes) => bytes.Length switch
        {
            0 => "(empty)",
            _ when IsPrintableAscii(bytes) => $"\"{Encoding.ASCII.GetString(bytes)}\"",
            <= 24 => Convert.ToHexString(bytes),
            _ => $"{Convert.ToHexString(bytes.AsSpan(0, 24))}… ({bytes.Length} bytes)",
        };

        private static bool IsPrintableAscii(byte[] bytes) =>
            bytes.Length > 0 && bytes.All(b => b is >= 0x20 and < 0x7F);
    }
}
