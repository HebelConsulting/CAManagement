using CAManagement.Pkcs11;
using CAManagement.Pkcs11.Configuration;

namespace CAManagement.Tests.Integration;

/// <summary>
/// A token label is a NAME, and two tokens wearing one name is an ambiguity the caller cannot see. Picking
/// either would open a session on keys that merely look right — and for an envelope-encryption consumer
/// that means wrapping against one token and failing to unwrap against another: silently unreadable data,
/// with every call returning success.
/// </summary>
/// <remarks>
/// Not hypothetical. SimplArchiveEncryption's provisioning script tested "does this token exist?" with a
/// pattern anchored immediately after the label, which never matched because SoftHSM pads labels with
/// trailing spaces — so every restart created ANOTHER token with the same label, and the service minted
/// fresh KEKs against whichever slot came first (2026-09-23: three tokens labelled "encryption").
/// </remarks>
[Collection(SoftHsmCollection.Name)]
public sealed class AmbiguousTokenLabelTests(SoftHsmFixture fixture)
{
    [Fact]
    public void Two_tokens_with_one_label_are_refused_rather_than_guessed_between()
    {
        var label = $"ambiguous-{Guid.NewGuid():N}"[..20];
        fixture.InitializeToken(label);
        fixture.InitializeToken(label);

        var options = fixture.CreateOptions();
        options.TokenLabel = label;

        var thrown = Assert.Throws<InvalidOperationException>(() =>
        {
            using var library = new Pkcs11Library(options);
            using var session = library.OpenSession();
        });

        // The message must name the ambiguity and the way out — it stands in for a silent wrong answer.
        Assert.Contains("2 tokens are labelled", thrown.Message);
        Assert.Contains(label, thrown.Message);
        Assert.Contains("SlotId", thrown.Message);
    }

    [Fact]
    public void One_token_with_that_label_still_resolves()
    {
        var label = $"unique-{Guid.NewGuid():N}"[..17];
        fixture.InitializeToken(label);

        var options = fixture.CreateOptions();
        options.TokenLabel = label;

        using var library = new Pkcs11Library(options);
        using var session = library.OpenSession();
        Assert.True(session.Handle > 0);
    }
}
