using CAManagement.Cli.Infrastructure;

namespace CAManagement.Tests.Unit;

/// <summary>
/// A logged command line must not carry the PIN or the management key it was given (#21).
/// </summary>
/// <remarks>
/// The tests are written the way the standing rule says to verify this: run with a KNOWN secret and assert
/// that string appears nowhere in the output. Two plausible redaction rules have leaked before on exactly
/// this shape, and both were found by reading real output rather than by a test written from the same
/// assumption as the code — so the assertions below are about the absence of a literal, not about the shape
/// of the result.
/// </remarks>
public sealed class ArgvRedactionTests
{
    private const string Pin = "654321";
    private const string ManagementKey = "0102030405060708010203040506070801020304050607080";

    [Fact]
    public void A_separated_secret_value_is_replaced_and_its_flag_is_kept()
    {
        var line = ArgvRedaction.Of("ykman", ["piv", "keys", "generate", "-P", Pin, "-m", ManagementKey, "9d", "pub.pem"]);

        Assert.DoesNotContain(Pin, line);
        Assert.DoesNotContain(ManagementKey, line);

        // The flags survive: an administrator needs to see THAT a credential was supplied and which option
        // carried it, or a failed authentication names nothing.
        Assert.Contains("-P ***", line);
        Assert.Contains("-m ***", line);

        // And everything that is not a secret is still readable, which is the whole reason for logging.
        Assert.Contains("piv keys generate", line);
        Assert.Contains("9d", line);
    }

    [Fact]
    public void An_ATTACHED_secret_value_is_replaced_too()
    {
        // The half that is easy to miss, and missing it is worse than having no redactor: the rule reads as
        // enforced while one spelling walks straight through.
        var line = ArgvRedaction.Of("ykman", ["piv", "access", $"--pin={Pin}", $"--management-key={ManagementKey}"]);

        Assert.DoesNotContain(Pin, line);
        Assert.DoesNotContain(ManagementKey, line);
        Assert.Contains("--pin=***", line);
        Assert.Contains("--management-key=***", line);
    }

    [Fact]
    public void A_secret_that_LOOKS_like_an_argument_does_not_blank_the_argument()
    {
        // Why the rule is by NAME. Redacting by VALUE — "find the PIN string and blank it" — blanks the slot
        // when the PIN happens to be `9d`, which is a legal PIN and a real slot. The command then reads as
        // though it operated on nothing.
        var line = ArgvRedaction.Of("ykman", ["piv", "keys", "generate", "-P", "9d", "9d", "pub.pem"]);

        Assert.Equal("ykman piv keys generate -P *** 9d pub.pem", line);
    }

    [Fact]
    public void Redaction_does_not_depend_on_where_the_option_appears()
    {
        // Why the rule is not by POSITION: the same secret moves when options are reordered, and an option
        // order is not part of anybody's contract.
        var first = ArgvRedaction.Of("ykman", ["-P", Pin, "piv", "info"]);
        var last = ArgvRedaction.Of("ykman", ["piv", "info", "-P", Pin]);

        Assert.DoesNotContain(Pin, first);
        Assert.DoesNotContain(Pin, last);
    }

    [Fact]
    public void An_unrecognised_option_is_LOGGED_rather_than_guessed_at()
    {
        // The deliberate direction of failure. A flag this list does not know is rendered in full, so a new
        // secret-bearing option shows up in a log where somebody can see it and add it here. The alternative
        // — blanking anything that looks secret — hides both the leak and the omission.
        var line = ArgvRedaction.Of("ykman", ["piv", "--some-new-option", "visible-value"]);

        Assert.Contains("--some-new-option visible-value", line);
    }

    [Fact]
    public void A_trailing_secret_option_with_no_value_still_names_itself()
    {
        // Malformed input, and it must not throw: this runs on the way to a log line, so a crash here would
        // take out the diagnostic rather than the command.
        Assert.Equal("ykman piv info --pin", ArgvRedaction.Of("ykman", ["piv", "info", "--pin"]));
    }

    [Fact]
    public void A_value_containing_an_equals_sign_does_not_leak_its_tail()
    {
        // The attached form is cut at the FIRST '=' — cutting at the last would keep everything before it.
        var line = ArgvRedaction.Of("ykman", ["piv", "--pin=abc=def=ghi"]);

        Assert.DoesNotContain("abc", line);
        Assert.DoesNotContain("def", line);
        Assert.DoesNotContain("ghi", line);
        Assert.Equal("ykman piv --pin=***", line);
    }
}
