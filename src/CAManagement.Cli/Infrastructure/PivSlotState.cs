
namespace CAManagement.Cli.Infrastructure;

/// <summary>What a PIV slot currently holds, as far as <c>ykman piv info</c> can be trusted to say (#21).</summary>
/// <param name="Slot">The slot this describes, lower-case hex as ykman spells it (<c>9d</c>).</param>
/// <param name="KeyPresence">Whether a private key is there — and note that this can be <b>Unknown</b>.</param>
/// <param name="PrivateKeyType">The algorithm ykman reported, e.g. <c>ECCP256</c>, or null when it said none.</param>
/// <param name="PublicKeyType">
/// The algorithm ykman reported for the slot's PUBLIC key. Reported even on an applet that withholds private
/// key metadata — measured on firmware 5.2.6, which printed <c>Private key type: EMPTY</c> beside
/// <c>Public key type: RSA2048</c>. Read from the slot's CERTIFICATE there, so it describes what the slot is
/// addressed as rather than proving the private key is present; it is evidence the slot is occupied, not
/// evidence the key is usable.
/// </param>
/// <param name="CertificateSubject">The certificate's subject, or null when the slot holds no certificate.</param>
/// <param name="FirmwareVersion">The PIV applet version, which decides whether the key answer is reliable.</param>
public sealed record PivSlotState(
    string Slot,
    KeyPresence KeyPresence,
    string? PrivateKeyType,
    string? PublicKeyType,
    string? CertificateSubject,
    Version? FirmwareVersion)
{
    /// <summary>True when this slot holds a certificate — which is independent of holding a key.</summary>
    /// <remarks>
    /// Independent because the two are genuinely separable on a PIV card, and the distinction is what makes
    /// the fix for a wrong-usage certificate non-destructive: re-issuing and importing replaces the
    /// certificate and leaves the key, so a card carrying a <c>digitalSignature</c>-only certificate (#18)
    /// can be corrected without losing the key it names. Only <c>keys generate</c> destroys a key.
    /// </remarks>
    public bool HasCertificate => CertificateSubject is not null;

    /// <summary>
    /// Whether it is safe to generate a key here without being told to (<see cref="KeyPresence.Absent"/>).
    /// </summary>
    /// <remarks>
    /// <b>Unknown is treated as occupied</b>, deliberately. Generating a key is the one irreversible step in
    /// provisioning, and the cost of the two mistakes is not symmetric: refusing a genuinely empty slot
    /// wastes a flag, while generating over a key that was there destroys the only copy of it.
    /// </remarks>
    public bool SafeToGenerateWithoutForce => KeyPresence == KeyPresence.Absent;
}

/// <summary>Whether a slot holds a private key — with the third answer that the hardware forces.</summary>
public enum KeyPresence
{
    /// <summary>
    /// ykman said there is no key, <b>and its firmware is new enough for that to mean something</b>.
    /// </summary>
    Absent = 0,

    /// <summary>ykman reported a key type, so a key is certainly there.</summary>
    Present = 1,

    /// <summary>
    /// ykman said <c>EMPTY</c> on firmware older than 5.3, where it says that <b>whether or not</b> the key
    /// exists.
    /// </summary>
    /// <remarks>
    /// Measured on hardware: a nano on firmware below 5.3 reported <c>Private key type: EMPTY</c> for a slot
    /// whose key demonstrably decrypted a real CMS envelope. The applet simply does not report key metadata
    /// before 5.3, so the field is silence rather than a negative — and only a decryption settles it.
    /// Treating it as <see cref="Absent"/> would make <c>provision</c> destroy a working key on exactly the
    /// cards that cannot tell it not to.
    /// </remarks>
    Unknown = 2,
}

/// <summary>Reads <c>ykman piv info</c> output. Its own type so the parsing can be tested without a card.</summary>
/// <remarks>
/// A parser over tool output is a wire format by another name: it changes between tool versions, and the
/// failure mode is a wrong answer rather than an exception. So it is fed real captured output in tests, and
/// it answers <see cref="KeyPresence.Unknown"/> rather than guessing whenever the text does not actually say.
/// </remarks>
public static class PivInfo
{
    /// <summary>The firmware from which <c>Private key type</c> means anything at all.</summary>
    private static readonly Version KeyMetadataFrom = new(5, 3);

    public static PivSlotState Read(string ykmanPivInfo, string slot)
    {
        var firmware = FirmwareOf(ykmanPivInfo);
        var block = BlockFor(ykmanPivInfo, slot);

        if (block.Count == 0)
        {
            // ykman prints no block for a slot it has nothing to say about. That is not "empty" on an old
            // applet, for the reason KeyPresence.Unknown exists.
            return new PivSlotState(slot, PresenceOf(null, firmware), null, null, null, firmware);
        }

        var keyType = ValueOf(block, "Private key type");
        var publicKeyType = ValueOf(block, "Public key type");
        var subject = ValueOf(block, "Subject DN");

        return new PivSlotState(
            slot,
            PresenceOf(keyType, firmware),
            // EMPTY is ykman's way of saying nothing, not an algorithm name, so it must not be reported as one.
            Named(keyType),
            Named(publicKeyType),
            subject,
            firmware);
    }

    /// <summary>An algorithm name, or null where ykman wrote its placeholder for "nothing to say".</summary>
    private static string? Named(string? value) =>
        value is { Length: > 0 } && !string.Equals(value, "EMPTY", StringComparison.OrdinalIgnoreCase)
            ? value
            : null;

    private static KeyPresence PresenceOf(string? keyType, Version? firmware)
    {
        if (keyType is { Length: > 0 } && !string.Equals(keyType, "EMPTY", StringComparison.OrdinalIgnoreCase))
        {
            return KeyPresence.Present;
        }

        // "EMPTY", or nothing said at all. Believe it only where the applet is new enough to report key
        // metadata — and where the firmware itself could not be read, believe nothing.
        return firmware is not null && firmware >= KeyMetadataFrom
            ? KeyPresence.Absent
            : KeyPresence.Unknown;
    }

    /// <summary>The applet version, or null when the output does not carry one.</summary>
    private static Version? FirmwareOf(string info)
    {
        foreach (var line in info.Split('\n'))
        {
            // ykman has spelled this "PIV version" and "PIV applet version" across releases; match the shape
            // rather than either exact phrase, since getting it wrong silently downgrades every slot answer
            // to Unknown.
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("PIV ", StringComparison.OrdinalIgnoreCase)
                || trimmed.IndexOf("version", StringComparison.OrdinalIgnoreCase) < 0)
            {
                continue;
            }

            var value = trimmed[(trimmed.IndexOf(':', StringComparison.Ordinal) + 1)..].Trim();
            if (Version.TryParse(value, out var parsed))
            {
                return parsed;
            }
        }

        return null;
    }

    /// <summary>The indented lines under <c>Slot 9d…</c>, whichever way this ykman spells the heading.</summary>
    private static List<string> BlockFor(string info, string slot)
    {
        var lines = info.Split('\n');
        var block = new List<string>();
        var inside = false;

        foreach (var line in lines)
        {
            var isSlotHeading = line.TrimStart().StartsWith("Slot ", StringComparison.OrdinalIgnoreCase);
            if (isSlotHeading)
            {
                // Older ykman writes "Slot 9d:", newer "Slot 9D (KEY MANAGEMENT):" — compare only the hex.
                var heading = line.Trim();
                var after = heading["Slot ".Length..].TrimStart();
                var hex = new string([.. after.TakeWhile(Uri.IsHexDigit)]);
                inside = string.Equals(hex, slot, StringComparison.OrdinalIgnoreCase);
                continue;
            }

            if (inside && line.Length > 0 && char.IsWhiteSpace(line[0]))
            {
                block.Add(line);
            }
            else if (inside && line.Trim().Length > 0)
            {
                inside = false; // an unindented line ends the block
            }
        }

        return block;
    }

    private static string? ValueOf(List<string> block, string label)
    {
        foreach (var line in block)
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith(label, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var colon = trimmed.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0)
            {
                continue;
            }

            var value = trimmed[(colon + 1)..].Trim();
            return value.Length == 0 ? null : value;
        }

        return null;
    }

    /// <summary>How a slot's contents read in a refusal — the information the owner asked to be printed.</summary>
    public static string Describe(PivSlotState state) => state switch
    {
        { KeyPresence: KeyPresence.Unknown } =>
            $"slot {state.Slot} may already hold a private key — this YubiKey's PIV applet "
            + $"({state.FirmwareVersion?.ToString(3) ?? "version unknown"}) does not report key metadata, so "
            + "'EMPTY' there means 'not said', not 'not present'"
            + (state.PublicKeyType is { } published ? $"; the slot is addressed as {published}" : string.Empty)
            + (state.HasCertificate ? $"; its certificate is {state.CertificateSubject}" : string.Empty),

        { KeyPresence: KeyPresence.Present } =>
            $"slot {state.Slot} holds a {state.PrivateKeyType} private key"
            + (state.HasCertificate
                ? $" and a certificate for {state.CertificateSubject}"
                : " and no certificate"),

        _ when state.HasCertificate =>
            $"slot {state.Slot} holds a certificate for {state.CertificateSubject} but no private key",

        _ => $"slot {state.Slot} is empty",
    };

}
