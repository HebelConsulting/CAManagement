using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CAManagement.Cli.Infrastructure;

namespace CAManagement.Tests.Unit;

/// <summary>
/// The enrolment manifest this CA writes for SimplArchive's bulk import (#21, SimplArchive#1501).
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the PRODUCER's statement of the wire shape, and it is deliberately not shared with the
/// consumer.</b> The two repositories have no common package, and a test that reads both sides from one
/// source agrees at every version while the wire disagrees — so the consumer has its own literal fixture
/// (<c>SimplArchive.UnitTests.CertificateManifestTests</c>) and this side asserts the literal JSON it
/// produces. A drift shows up as one of the two fixtures failing rather than as an import that silently
/// enrols nothing.
/// </para>
/// <para>
/// The property NAMES are the contract, so they are asserted as text rather than through a round trip
/// against this same type — which would pass whatever they were renamed to.
/// </para>
/// </remarks>
public sealed class EnrolmentManifestTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"ca-manifest-{Guid.NewGuid():N}.json");

    public void Dispose() => File.Delete(_path);

    private static X509Certificate2 Certificate(string subject = "CN=anna@acme.test")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    [Fact]
    public void The_file_carries_exactly_the_field_names_the_consumer_reads()
    {
        using var certificate = Certificate();
        var manifest = new EnrolmentManifest();
        manifest.RecordIssued("anna@acme.test", "YubiKey 5C", certificate);
        manifest.RecordRevoked("2334CB43CDEC7428", new DateTimeOffset(2026, 9, 30, 19, 36, 21, TimeSpan.Zero), "KeyCompromise");
        manifest.Write(_path);

        var document = JsonDocument.Parse(File.ReadAllText(_path)).RootElement;

        // The two collections, spelled as the consumer's reader expects.
        var issued = Assert.Single(document.GetProperty("issued").EnumerateArray().ToList());
        Assert.Equal("anna@acme.test", issued.GetProperty("holder").GetString());
        Assert.Equal("YubiKey 5C", issued.GetProperty("label").GetString());
        Assert.Equal(certificate.SerialNumber.ToUpperInvariant(), issued.GetProperty("serial").GetString());
        Assert.Equal(certificate.Thumbprint, issued.GetProperty("thumbprint").GetString());
        Assert.Contains("BEGIN CERTIFICATE", issued.GetProperty("certificatePem").GetString()!, StringComparison.Ordinal);

        var revoked = Assert.Single(document.GetProperty("revoked").EnumerateArray().ToList());
        Assert.Equal("2334CB43CDEC7428", revoked.GetProperty("serial").GetString());
        Assert.Equal("KeyCompromise", revoked.GetProperty("reason").GetString());
        Assert.Equal(
            new DateTimeOffset(2026, 9, 30, 19, 36, 21, TimeSpan.Zero),
            revoked.GetProperty("at").GetDateTimeOffset());
    }

    [Fact]
    public void A_private_key_is_never_written_even_when_the_certificate_object_holds_one()
    {
        // The certificate built above has its private key attached in memory, which is exactly the situation
        // in which a careless PEM export leaks one. The consumer REFUSES a manifest containing a private key,
        // and this is the side that must never produce one — a manifest is a file an operator copies to
        // another machine and POSTs over a wire.
        using var certificate = Certificate();
        Assert.True(certificate.HasPrivateKey, "the fixture must hold a private key for this to prove anything");

        var manifest = new EnrolmentManifest();
        manifest.RecordIssued("anna@acme.test", "YubiKey 5C", certificate);
        manifest.Write(_path);

        var written = File.ReadAllText(_path);

        Assert.Contains("BEGIN CERTIFICATE", written, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE KEY", written, StringComparison.Ordinal);
    }

    [Fact]
    public void Re_provisioning_the_same_card_REPLACES_its_row_rather_than_adding_one()
    {
        // Provisioning is re-run: a wrong key usage is repaired, an expiring certificate is replaced. Two
        // rows for one serial would enrol the same certificate twice and leave the operator to work out
        // which is current.
        using var certificate = Certificate();
        var manifest = new EnrolmentManifest();
        manifest.RecordIssued("anna@acme.test", "first label", certificate);
        manifest.RecordIssued("anna@acme.test", "second label", certificate);

        var row = Assert.Single(manifest.Issued);
        Assert.Equal("second label", row.Label);
    }

    [Fact]
    public void A_second_revocation_of_one_serial_does_not_accumulate()
    {
        var manifest = new EnrolmentManifest();
        manifest.RecordRevoked("aa:bb", DateTimeOffset.UnixEpoch, "Superseded");
        manifest.RecordRevoked("AABB", DateTimeOffset.UnixEpoch.AddDays(1), "KeyCompromise");

        var row = Assert.Single(manifest.Revoked);
        Assert.Equal("AABB", row.Serial);
        Assert.Equal("KeyCompromise", row.Reason);
    }

    [Theory]
    [InlineData("2c:ef:64:10", "2CEF6410")]
    [InlineData("0x2cef6410", "2CEF6410")]
    [InlineData("2cef-6410", "2CEF6410")]
    [InlineData("  2cef6410  ", "2CEF6410")]
    public void A_serial_is_normalised_the_way_the_consumer_normalises_it(string given, string expected) =>
        Assert.Equal(expected, EnrolmentManifest.NormaliseSerial(given));

    [Fact]
    public void LEADING_ZEROS_SURVIVE()
    {
        // A serial is an opaque octet string rendered as hex, not a number. `X509Certificate2.SerialNumber`
        // keeps every byte, and a real test card's begins `00000000221971BD` — four zero bytes. Trimming
        // them is the reflex, and it would make that certificate fail to match its own enrolment.
        Assert.Equal("00000000221971BD", EnrolmentManifest.NormaliseSerial("00000000221971bd"));
    }

    [Fact]
    public void An_absent_manifest_is_the_normal_first_case()
    {
        // Created by the first issuance rather than requiring a set-up step.
        var manifest = EnrolmentManifest.Read(_path);

        Assert.Empty(manifest.Issued);
        Assert.Empty(manifest.Revoked);
    }

    [Fact]
    public void An_existing_manifest_is_APPENDED_to_across_invocations()
    {
        using var first = Certificate("CN=anna@acme.test");
        using var second = Certificate("CN=tom@acme.test");

        var one = EnrolmentManifest.Read(_path);
        one.RecordIssued("anna@acme.test", "YubiKey 5C", first);
        one.Write(_path);

        var two = EnrolmentManifest.Read(_path);
        two.RecordIssued("tom@acme.test", "YubiKey 5 Nano", second);
        two.Write(_path);

        var reread = EnrolmentManifest.Read(_path);
        Assert.Equal(2, reread.Issued.Count);
        Assert.Contains(reread.Issued, row => row.Holder == "anna@acme.test");
        Assert.Contains(reread.Issued, row => row.Holder == "tom@acme.test");
    }

    [Fact]
    public void A_manifest_that_cannot_be_parsed_is_NOT_overwritten()
    {
        // It records issuances that may already have been handed over. Silently starting a fresh file would
        // discard the only record of them, which is the one thing this file exists to keep.
        File.WriteAllText(_path, "{ this is not json");

        var refusal = Assert.Throws<InvalidOperationException>(() => EnrolmentManifest.Read(_path));

        Assert.Contains("not overwritten", refusal.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("{ this is not json", File.ReadAllText(_path));
    }

    [Fact]
    public void The_file_the_consumers_OWN_fixture_shows_is_the_file_this_writes()
    {
        // Cross-checked by hand against SimplArchive.UnitTests.CertificateManifestTests' literal fixture,
        // which is the consumer's statement of what it accepts. The keys below are that fixture's keys; if
        // this list and that one ever disagree, one of the two tests fails and the import does not silently
        // enrol nothing.
        using var certificate = Certificate();
        var manifest = new EnrolmentManifest();
        manifest.RecordIssued("anna@acme.test", "YubiKey 5C", certificate);
        manifest.RecordRevoked("2334CB43CDEC7428", DateTimeOffset.UtcNow, "KeyCompromise");
        manifest.Write(_path);

        var root = JsonDocument.Parse(File.ReadAllText(_path)).RootElement;

        Assert.Equal(
            ["issued", "revoked"],
            root.EnumerateObject().Select(p => p.Name).Order());
        Assert.Equal(
            ["certificatePem", "holder", "label", "serial", "thumbprint"],
            root.GetProperty("issued")[0].EnumerateObject().Select(p => p.Name).Order());
        Assert.Equal(
            ["at", "reason", "serial"],
            root.GetProperty("revoked")[0].EnumerateObject().Select(p => p.Name).Order());
    }
}
