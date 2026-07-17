using System.Text.Json;
using System.Text.Json.Serialization;
using CAManagement.X509;

namespace CAManagement.Cli.Infrastructure;

/// <summary>
/// The console's CA bookkeeping (the CAManagement.X509 library itself is
/// stateless per SPEC D5): last issued CRL number and the revocation list.
/// </summary>
public sealed class CaStateFile
{
    public ulong CrlNumber { get; set; }

    public List<RevokedEntry> Revoked { get; set; } = [];

    public sealed record RevokedEntry(string SerialHex, DateTimeOffset RevokedAtUtc, RevocationReason Reason);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static CaStateFile Load(string path) => File.Exists(path)
        ? JsonSerializer.Deserialize<CaStateFile>(File.ReadAllText(path), JsonOptions)
          ?? throw new InvalidOperationException($"CA state file '{path}' is empty or invalid.")
        : new CaStateFile();

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOptions));
}
