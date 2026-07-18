using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CAManagement.X509;

namespace CAManagement.Cli.Infrastructure;

/// <summary>
/// The console's CA bookkeeping (the CAManagement.X509 library itself is
/// stateless per SPEC D5): last issued CRL number and the revocation list.
/// Persisted by an <see cref="ICaStateStore"/> — a JSON file or a data object
/// on the token.
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

    public byte[] ToJson() => Encoding.UTF8.GetBytes(JsonSerializer.Serialize(this, JsonOptions));

    public static CaStateFile FromJson(byte[] json) =>
        JsonSerializer.Deserialize<CaStateFile>(Encoding.UTF8.GetString(json), JsonOptions)
        ?? throw new InvalidOperationException("The CA state is empty or invalid.");

    public static CaStateFile Load(string path) => File.Exists(path)
        ? FromJson(File.ReadAllBytes(path))
        : new CaStateFile();

    public void Save(string path) => File.WriteAllBytes(path, ToJson());
}
