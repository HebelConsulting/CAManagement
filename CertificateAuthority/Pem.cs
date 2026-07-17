using System.Security.Cryptography;

namespace CertificateAuthority;

/// <summary>Minimal PEM helpers (RFC 7468) on top of <see cref="PemEncoding"/>.</summary>
public static class Pem
{
    public static (string Label, byte[] Der)? TryDecodeFirst(string text) =>
        PemEncoding.TryFind(text, out var fields)
            ? (text[fields.Label], Convert.FromBase64String(text[fields.Base64Data]))
            : null;

    public static string Encode(string label, byte[] der) => new(PemEncoding.Write(label, der));
}
