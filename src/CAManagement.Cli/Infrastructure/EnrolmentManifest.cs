using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CAManagement.Cli.Infrastructure;

/// <summary>
/// What this CA hands over to SimplArchive: what it issued, and what it revoked (#21, SimplArchive#1501).
/// </summary>
/// <remarks>
/// <para>
/// <b>A file purpose-built for that import, not an extension of the CA's operating state</b>
/// (owner-decided). <c>ca-state.json</c> holds the CRL number and the revocation list — what the CA needs to
/// RUN — and holds no issued certificates and no e-mail addresses at all, which is exactly what the import
/// needs. Keeping them apart means the CA's own state cannot be broken by the consumer's requirements, and
/// the manifest can carry a holder's address, which is not a CA concept.
/// </para>
/// <para>
/// <b>The shape is deliberately NOT shared through a package.</b> The two repositories have none, and a test
/// that reads both sides from one source agrees at every version while the wire disagrees. So each side
/// defines it and each side tests against a LITERAL fixture of the file: this type is the producer's
/// statement, <c>SimplArchive.Cli.Commands.CertificateManifest</c> is the consumer's, and the two fixtures
/// are what catch a drift.
/// </para>
/// <para>
/// <b>Upserted by serial.</b> Provisioning is re-run — a card whose certificate carried the wrong key usage
/// gets a new one, an expiring certificate is replaced — and a manifest that grew a second row each time
/// would enrol the same certificate twice and leave the operator to work out which row is current.
/// </para>
/// </remarks>
public sealed class EnrolmentManifest
{
    /// <summary>Certificates this CA issued, each naming who holds it.</summary>
    [JsonPropertyName("issued")]
    public List<IssuedCertificate> Issued { get; set; } = [];

    /// <summary>Certificates this CA revoked, by serial — the only identifier a CA speaks.</summary>
    [JsonPropertyName("revoked")]
    public List<RevokedEntry> Revoked { get; set; } = [];

    public sealed class IssuedCertificate
    {
        /// <summary>The holder's e-mail: how SimplArchive names a user, and what a CA does not record.</summary>
        [JsonPropertyName("holder")]
        public string Holder { get; set; } = string.Empty;

        /// <summary>What the holder calls this key: "YubiKey 5C", "work laptop".</summary>
        [JsonPropertyName("label")]
        public string Label { get; set; } = string.Empty;

        /// <summary>Upper-case hex, no separators, <b>leading zeros kept</b> — see <see cref="SerialOf"/>.</summary>
        [JsonPropertyName("serial")]
        public string Serial { get; set; } = string.Empty;

        /// <summary>The certificate's thumbprint, for an operator reconciling two lists by eye.</summary>
        [JsonPropertyName("thumbprint")]
        public string Thumbprint { get; set; } = string.Empty;

        /// <summary>The certificate, PEM-encoded. Never a private key.</summary>
        [JsonPropertyName("certificatePem")]
        public string CertificatePem { get; set; } = string.Empty;
    }

    public sealed class RevokedEntry
    {
        [JsonPropertyName("serial")]
        public string Serial { get; set; } = string.Empty;

        [JsonPropertyName("at")]
        public DateTimeOffset At { get; set; }

        /// <summary>The CA's reason, carried for the operator's log. The consumer stores a date only.</summary>
        [JsonPropertyName("reason")]
        public string? Reason { get; set; }
    }

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Reads the manifest at <paramref name="path"/>, or an empty one when it does not exist yet.</summary>
    /// <remarks>
    /// An absent file is the normal first case, not an error: the manifest is created by the first issuance
    /// and grows from there. A file that exists but cannot be parsed IS an error — overwriting it would
    /// discard a record of real issuances, which is the one thing this file exists to keep.
    /// </remarks>
    public static EnrolmentManifest Read(string path)
    {
        if (!File.Exists(path))
        {
            return new EnrolmentManifest();
        }

        try
        {
            return JsonSerializer.Deserialize<EnrolmentManifest>(File.ReadAllText(path), Json)
                ?? new EnrolmentManifest();
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException(
                $"'{path}' exists but is not a readable enrolment manifest: {exception.Message}. It is not "
                + "overwritten, because it records issuances that may already have been handed over.");
        }
    }

    public void Write(string path)
    {
        if (Path.GetDirectoryName(Path.GetFullPath(path)) is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(path, JsonSerializer.Serialize(this, Json));
    }

    /// <summary>
    /// Records an issuance, replacing any row with the same serial.
    /// </summary>
    public void RecordIssued(string holder, string label, X509Certificate2 certificate)
    {
        var serial = SerialOf(certificate);
        Issued.RemoveAll(existing => string.Equals(existing.Serial, serial, StringComparison.Ordinal));
        Issued.Add(new IssuedCertificate
        {
            Holder = holder,
            Label = label,
            Serial = serial,
            Thumbprint = certificate.Thumbprint,
            // The PUBLIC certificate and nothing else. A private key in this file would be a private key in
            // something an operator copies to another machine and POSTs over a wire; the consumer refuses a
            // manifest containing one, and this is the side that must never write one.
            CertificatePem = X509Pem(certificate),
        });
    }

    /// <summary>Records a revocation, replacing any row with the same serial.</summary>
    public void RecordRevoked(string serial, DateTimeOffset at, string? reason)
    {
        var normalised = NormaliseSerial(serial);
        Revoked.RemoveAll(existing => string.Equals(existing.Serial, normalised, StringComparison.Ordinal));
        Revoked.Add(new RevokedEntry { Serial = normalised, At = at, Reason = reason });
    }

    /// <summary>The serial as both sides must spell it.</summary>
    /// <remarks>
    /// <b>LEADING ZEROS ARE SIGNIFICANT AND ARE KEPT.</b> A serial is an opaque octet string rendered as hex,
    /// not a number: <c>X509Certificate2.SerialNumber</c> keeps every byte, and a real test card's is
    /// <c>00000000221971BD…</c> — four zero bytes and all. Trimming them is the reflex, and it would make
    /// that certificate fail to match its own enrolment on the consumer's side.
    /// </remarks>
    public static string SerialOf(X509Certificate2 certificate) => NormaliseSerial(certificate.SerialNumber);

    /// <summary>Upper-case hex with separators and a <c>0x</c> prefix removed; nothing else changed.</summary>
    public static string NormaliseSerial(string serial)
    {
        var trimmed = serial.Trim()
            .Replace(":", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .Replace(" ", string.Empty, StringComparison.Ordinal);

        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[2..];
        }

        return trimmed.ToUpperInvariant();
    }

    private static string X509Pem(X509Certificate2 certificate) =>
        X509.Pem.Encode("CERTIFICATE", certificate.RawData);
}
