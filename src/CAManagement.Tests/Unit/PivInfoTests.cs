using CAManagement.Cli.Infrastructure;

namespace CAManagement.Tests.Unit;

/// <summary>
/// Reading <c>ykman piv info</c> — including the answer the hardware refuses to give (#21).
/// </summary>
/// <remarks>
/// <para>
/// Parsing a tool's human output is a wire format by another name: it moves between versions, and the
/// failure mode is a <i>wrong answer</i> rather than an exception. So these feed captured output rather than
/// output composed from the same assumptions as the parser.
/// </para>
/// <para>
/// The case that matters most is the third one. A YubiKey on firmware below 5.3 prints
/// <c>Private key type: EMPTY</c> <b>whether or not the key is there</b> — measured on a nano whose key
/// demonstrably decrypted a real CMS envelope. Reading that as "empty" would make <c>provision</c> generate
/// over it, and generation is the one step that destroys a key.
/// </para>
/// </remarks>
public sealed class PivInfoTests
{
    private const string Firmware574WithKeyAndCertificate = """
        PIV version:              5.7.4
        PIN tries remaining:      3/3
        Management key algorithm: AES192
        CHUID:	3019d4e739da739ced39ce739d836858
        Slot 9A (AUTHENTICATION):
          Private key type:     ECCP256
          Public key type:      ECCP256
          Subject DN:           CN=anna@acme.test
          Issuer DN:            CN=Acme Issuing CA
          Serial:               6039614611
          Not before:           2026-09-30T12:00:00
          Not after:            2027-09-30T12:00:00
        Slot 9D (KEY MANAGEMENT):
          Private key type:     ECCP256
          Public key type:      ECCP256
          Subject DN:           CN=anna@acme.test
          Issuer DN:            CN=Acme Issuing CA
          Serial:               6039614612
          Not before:           2026-09-30T12:00:00
          Not after:            2027-09-30T12:00:00
        """;

    private const string Firmware574EmptySlot = """
        PIV version:              5.7.4
        PIN tries remaining:      3/3
        Management key algorithm: AES192
        Slot 9A (AUTHENTICATION):
          Private key type:     ECCP256
          Public key type:      ECCP256
          Subject DN:           CN=anna@acme.test
        """;

    // The trap: firmware below 5.3 prints EMPTY regardless, and this card HAS a working key.
    private const string Firmware502SaysEmpty = """
        PIV version:              5.0.2
        PIN tries remaining:      3/3
        Slot 9D (KEY MANAGEMENT):
          Private key type:     EMPTY
          Public key type:      EMPTY
          Subject DN:           CN=alex@acme.test
          Issuer DN:            CN=Acme Issuing CA
          Serial:               6039614613
        """;

    /// <summary>
    /// Captured VERBATIM from a YubiKey 5C Nano, PIV applet 5.2.6, on 2026-10-01.
    /// </summary>
    /// <remarks>
    /// Written from the real tool's output rather than from memory of its format, which is the standing
    /// lesson about replaying your own assumptions: a fixture built by analogy passes while the real thing
    /// fails. Two details here were NOT what the hand-written fixtures above assumed — the heading spells the
    /// slot role with an underscore (<c>KEY_MANAGEMENT</c>), and <c>Public key type</c> is reported as
    /// <c>RSA2048</c> while <c>Private key type</c> says <c>EMPTY</c>.
    /// </remarks>
    private const string RealNano526 = """
        PIV version:              5.2.6
        PIN tries remaining:      3
        Management key algorithm: TDES
        CHUID: 3019d4e739da739ced39ce739d836858210842108421c84210c3eb34106d0c87bdcae64e24b1c3890c6e1e6ba0350832303330303130313e00fe00
        CCC:   f015a000000116ff0238705a0d55143eced242d2e57342f10121f20121f300f40100f50110f600f700fa00fb00fc00fd00fe00
        Slot 9D (KEY_MANAGEMENT):
          Private key type: EMPTY
          Public key type:  RSA2048
          Subject DN:       CN=crypt@demo.simplarchive.dev,OU=SimplArchive,O=Hebel Consulting GmbH,L=Kriens,ST=Luzern,C=CH
          Issuer DN:        CN=Hebel Consulting Test CA,O=Hebel Consulting GmbH,L=Kriens,ST=Luzern,C=CH
          Serial:           3237916680314442807 (0x2cef6410c6745437)
          Fingerprint:      ca5ff4effc791cdcd075c1dfcb747a10e3e59195181f59428a4c070d7bb01809
          Not before:       2026-09-30T19:10:27+00:00
          Not after:        2026-10-28T19:10:27+00:00
        """;

    [Fact]
    public void The_REAL_output_of_a_pre_5_3_card_is_read_correctly()
    {
        // The card this caveat exists for, and the output it actually produces. Everything the slot holds is
        // readable EXCEPT the one fact that would authorise destroying it.
        var state = PivInfo.Read(RealNano526, "9d");

        Assert.Equal(new Version(5, 2, 6), state.FirmwareVersion);
        Assert.Equal(KeyPresence.Unknown, state.KeyPresence);
        Assert.False(state.SafeToGenerateWithoutForce);

        // EMPTY is not an algorithm; RSA2048 is, and it comes from the slot's certificate rather than from
        // key metadata — so it says what the slot is ADDRESSED as, not that the private key is reachable.
        Assert.Null(state.PrivateKeyType);
        Assert.Equal("RSA2048", state.PublicKeyType);
        Assert.StartsWith("CN=crypt@demo.simplarchive.dev", state.CertificateSubject);
    }

    [Fact]
    public void The_refusal_for_that_card_tells_the_operator_everything_it_CAN_know()
    {
        // What the owner asked to be printed. All three facts are available on this card; only the
        // private key's existence is not, and the sentence has to be honest about which is which.
        var description = PivInfo.Describe(PivInfo.Read(RealNano526, "9d"));

        Assert.Contains("may already hold", description);
        Assert.Contains("5.2.6", description);
        Assert.Contains("RSA2048", description);
        Assert.Contains("crypt@demo.simplarchive.dev", description);
    }

    [Fact]
    public void A_populated_slot_on_a_current_applet_reports_its_key_and_certificate()
    {
        var state = PivInfo.Read(Firmware574WithKeyAndCertificate, "9d");

        Assert.Equal(KeyPresence.Present, state.KeyPresence);
        Assert.Equal("ECCP256", state.PrivateKeyType);
        Assert.Equal("CN=anna@acme.test", state.CertificateSubject);
        Assert.True(state.HasCertificate);
        Assert.False(state.SafeToGenerateWithoutForce);
    }

    [Fact]
    public void The_slot_read_is_the_slot_ASKED_FOR_and_not_the_first_one_printed()
    {
        // 9A comes first in the output and carries a DIFFERENT serial. Taking the first block is the classic
        // version of this bug, and it would report an authentication key as though it were the decryption one.
        var authentication = PivInfo.Read(Firmware574WithKeyAndCertificate, "9a");
        var keyManagement = PivInfo.Read(Firmware574WithKeyAndCertificate, "9d");

        Assert.Equal("9a", authentication.Slot);
        Assert.Equal("9d", keyManagement.Slot);
        Assert.Equal(KeyPresence.Present, authentication.KeyPresence);
    }

    [Fact]
    public void A_slot_the_output_does_not_mention_is_empty_on_a_current_applet()
    {
        var state = PivInfo.Read(Firmware574EmptySlot, "9d");

        Assert.Equal(KeyPresence.Absent, state.KeyPresence);
        Assert.Null(state.PrivateKeyType);
        Assert.False(state.HasCertificate);
        Assert.True(state.SafeToGenerateWithoutForce);
    }

    [Fact]
    public void EMPTY_on_an_OLD_applet_is_UNKNOWN_not_absent()
    {
        // The measured trap, and the reason KeyPresence has three members. Believing this card was empty
        // would destroy a key that works.
        var state = PivInfo.Read(Firmware502SaysEmpty, "9d");

        Assert.Equal(KeyPresence.Unknown, state.KeyPresence);
        Assert.False(state.SafeToGenerateWithoutForce);

        // EMPTY is not an algorithm name and must not be reported as one.
        Assert.Null(state.PrivateKeyType);

        // The certificate IS readable on such a card — only key metadata is withheld — so the refusal can
        // still tell the operator whose key it is about to destroy.
        Assert.Equal("CN=alex@acme.test", state.CertificateSubject);
    }

    [Fact]
    public void Output_with_no_readable_firmware_believes_NOTHING_about_the_key()
    {
        // Fails safe: an unparseable or renamed version line must not silently become "new enough", because
        // that turns the caveat above off for every card at once.
        var state = PivInfo.Read("Slot 9D (KEY MANAGEMENT):\n  Private key type:     EMPTY\n", "9d");

        Assert.Equal(KeyPresence.Unknown, state.KeyPresence);
        Assert.Null(state.FirmwareVersion);
        Assert.False(state.SafeToGenerateWithoutForce);
    }

    [Fact]
    public void The_older_heading_spelling_is_read_too()
    {
        // ykman has printed "Slot 9d:" and "Slot 9D (KEY MANAGEMENT):" across releases. Matching the hex
        // rather than either phrase is what keeps an upgrade from silently reporting every slot as empty.
        var state = PivInfo.Read("PIV version: 5.7.4\nSlot 9d:\n  Private key type: RSA2048\n", "9d");

        Assert.Equal(KeyPresence.Present, state.KeyPresence);
        Assert.Equal("RSA2048", state.PrivateKeyType);
    }

    [Fact]
    public void The_description_says_which_of_the_three_states_it_is()
    {
        // This text is what the owner asked to be printed before a refusal, so it has to distinguish "there
        // is a key here" from "there may be a key here" — advice that conflates them is advice to guess.
        Assert.Contains("holds a ECCP256 private key",
            PivInfo.Describe(PivInfo.Read(Firmware574WithKeyAndCertificate, "9d")));

        var unknown = PivInfo.Describe(PivInfo.Read(Firmware502SaysEmpty, "9d"));
        Assert.Contains("may already hold", unknown);
        Assert.Contains("does not report key metadata", unknown);
        Assert.Contains("alex@acme.test", unknown);

        Assert.Contains("is empty", PivInfo.Describe(PivInfo.Read(Firmware574EmptySlot, "9d")));
    }
}
