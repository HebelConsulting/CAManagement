using CAManagement.Cli.Commands;
using Spectre.Console.Cli;

namespace CAManagement.Tests.Unit;

/// <summary>
/// The guardrails on <c>wipe-token</c>. They are the whole safety surface of a verb that destroys
/// every key on a token with no undo, so each refusal is pinned rather than left to review.
/// </summary>
public sealed class WipeTokenSettingsTests
{
    private static WipeTokenCommand.Settings Settings(
        NativeULong? slot = 7, string? tokenLabel = null, string soPin = "12345678",
        string newLabel = "retired", bool yes = true) =>
        new() { Slot = slot, TokenLabel = tokenLabel, SoPin = soPin, NewLabel = newLabel, Yes = yes };

    [Fact]
    public void A_slot_is_mandatory()
    {
        var result = Settings(slot: null).Validate();

        Assert.False(result.Successful);
        Assert.Contains("--slot", result.Message);
    }

    [Fact] // the point of the verb is to resolve an ambiguous label — resolving BY label would pick at random
    public void Addressing_by_token_label_is_refused()
    {
        var result = Settings(tokenLabel: "encryption").Validate();

        Assert.False(result.Successful);
        Assert.Contains("--token-label", result.Message);
    }

    [Fact]
    public void Confirmation_is_mandatory()
    {
        var result = Settings(yes: false).Validate();

        Assert.False(result.Successful);
        Assert.Contains("--yes", result.Message);
    }

    [Fact]
    public void A_new_label_is_mandatory()
    {
        var result = Settings(newLabel: "").Validate();

        Assert.False(result.Successful);
        Assert.Contains("--new-label", result.Message);
    }

    [Fact]
    public void A_slot_with_confirmation_validates()
    {
        Assert.True(Settings().Validate().Successful);
    }
}
