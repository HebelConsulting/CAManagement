using System.Security.Cryptography;

namespace CAManagement.X509;

/// <summary>Minimal PEM helpers (RFC 7468) on top of <see cref="PemEncoding"/>.</summary>
public static class Pem
{
    public static (string Label, byte[] Der)? TryDecodeFirst(string text) =>
        PemEncoding.TryFind(text, out var fields)
            ? (text[fields.Label], Convert.FromBase64String(text[fields.Base64Data]))
            : null;

    /// <summary>All PEM blocks in the text, in order (e.g. a CA bundle).</summary>
    public static IReadOnlyList<(string Label, byte[] Der)> DecodeAll(string text)
    {
        var blocks = new List<(string Label, byte[] Der)>();
        var offset = 0;

        while (offset < text.Length && PemEncoding.TryFind(text.AsSpan(offset), out var fields))
        {
            var span = text.AsSpan(offset);
            blocks.Add((new string(span[fields.Label]), Convert.FromBase64String(new string(span[fields.Base64Data]))));
            offset += fields.Location.End.GetOffset(span.Length);
        }

        return blocks;
    }

    public static string Encode(string label, byte[] der) => new(PemEncoding.Write(label, der));
}
