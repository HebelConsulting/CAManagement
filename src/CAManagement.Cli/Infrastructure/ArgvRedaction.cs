namespace CAManagement.Cli.Infrastructure;

/// <summary>
/// Renders a child process's command line for a log with its secrets removed — by argument NAME (#21).
/// </summary>
/// <remarks>
/// <para>
/// An administrator is entitled to see what was done to their token, so the commands this tool drives are
/// echoed. But a PIN and a management key ride on <b>argv</b> (<c>-P 123456</c>, <c>-m 0102…</c>), so echoing
/// the command line verbatim writes credentials into a log — and a console log is exactly where nobody looks
/// for them afterwards.
/// </para>
/// <para>
/// <b>By NAME, and nothing whitelisted.</b> The two obvious alternatives both fail: redacting by POSITION
/// breaks the moment an option order changes, and redacting by VALUE means a PIN of <c>9d</c> blanks the slot
/// argument instead. Matching the flag and blanking what follows it fails the safe way round — an
/// unrecognised flag is logged, which is visible and fixable, rather than a secret being kept by luck.
/// </para>
/// <para>
/// <b>Both spellings.</b> A separated value (<c>--pin 123456</c>) and an attached one (<c>--pin=123456</c>)
/// are the same secret, and a redactor that handles one is worse than none: it reads as though the rule is
/// enforced.
/// </para>
/// <para>
/// The flag itself is kept and rendered with <c>***</c>, deliberately — the reader still learns that a
/// credential was supplied and which option carried it, which is what makes a failed authentication
/// diagnosable at all.
/// </para>
/// </remarks>
public static class ArgvRedaction
{
    /// <summary>
    /// Options whose value is a secret. Short forms included: <c>ykman piv</c> takes <c>-P</c> for the PIN and
    /// <c>-m</c> for the management key, which is how they are actually typed.
    /// </summary>
    private static readonly HashSet<string> SecretOptions = new(StringComparer.Ordinal)
    {
        "-P", "--pin",
        "-m", "--management-key",
        "-n", "--new-pin",
        "--puk", "--new-puk",
        "--so-pin",
        "--password",
    };

    /// <summary>The command line as it may be logged: every secret value replaced by <c>***</c>.</summary>
    public static string Of(string executable, IReadOnlyList<string> arguments)
    {
        var rendered = new List<string>(arguments.Count) { executable };
        var blankNext = false;

        foreach (var argument in arguments)
        {
            if (blankNext)
            {
                rendered.Add("***");
                blankNext = false;
                continue;
            }

            // The attached form, cut at the FIRST '=' so a value containing '=' cannot leak its tail.
            if (argument.IndexOf('=', StringComparison.Ordinal) is > 0 and var equals
                && SecretOptions.Contains(argument[..equals]))
            {
                rendered.Add($"{argument[..equals]}=***");
                continue;
            }

            rendered.Add(argument);
            blankNext = SecretOptions.Contains(argument);
        }

        // A trailing secret option with no value: the flag is still shown, because its presence is the part
        // worth knowing and inventing a value to hide would be a lie about what ran.
        return string.Join(' ', rendered);
    }
}
