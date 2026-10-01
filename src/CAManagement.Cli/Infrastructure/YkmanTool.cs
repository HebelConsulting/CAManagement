using System.Diagnostics;
using Spectre.Console;

namespace CAManagement.Cli.Infrastructure;

/// <summary>The result of one <c>ykman</c> invocation.</summary>
public sealed record YkmanResult(int ExitCode, string Output, string Error)
{
    public bool Succeeded => ExitCode == 0;

    /// <summary>Everything the tool said, for a caller that has to parse it.</summary>
    public string All => string.IsNullOrEmpty(Error) ? Output : $"{Output}\n{Error}";
}

/// <summary>
/// Drives <c>ykman</c>, the PIV applet's own tool, and logs every command and response (#21).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why an external tool rather than PKCS#11 or PC/SC.</b> A YubiKey cannot be provisioned over PKCS#11 at
/// all: <c>libykcs11</c> does not implement <c>C_GenerateKeyPair</c> for PIV slots and cannot even *see* an
/// empty slot, because it enumerates slots by the certificates in them; <c>C_InitToken</c> is unsupported
/// outright. Provisioning is the PIV applet protocol — management-key authentication, <c>GENERATE ASYMMETRIC
/// KEY PAIR</c>, <c>PUT DATA</c> — and there is no PC/SC or APDU code in this repository. Writing it would be
/// days of native interop on three platforms for a step that is already scripted and proven on hardware.
/// </para>
/// <para>
/// <b>The command shape is what makes this safe to choose.</b> <c>caconsole yubikey provision</c> hides the
/// mechanism completely, so moving to native PIV later changes nothing for the caller.
/// </para>
/// <para>
/// <b>The dependency is a NAMED, CHECKED prerequisite</b>, not an assumption — ADR 0611's rule about
/// installing through the host's package manager applies to how it gets there, so the refusal names the
/// package rather than a download.
/// </para>
/// <para>
/// <b>Every command and its response are echoed</b> (owner, 2026-09-30): an administrator is entitled to see
/// what was done to their token. The line goes through <see cref="ArgvRedaction"/>, because the PIN and the
/// management key ride on argv.
/// </para>
/// </remarks>
public sealed class YkmanTool(string executable = "ykman")
{
    /// <summary>What a reader is told when the tool is missing — the package, per host.</summary>
    /// <remarks>
    /// Named per platform because "install ykman" is the instruction that sends somebody to a download page,
    /// which is precisely what ADR 0611 exists to prevent: what a package manager installed can be queried,
    /// upgraded, audited and removed, and what a script installed cannot.
    /// </remarks>
    internal const string InstallHint =
        "Install it through the host's package manager — 'dnf install yubikey-manager' on Rocky/RHEL, "
        + "'apt-get install yubikey-manager' on Debian/Ubuntu, 'brew install ykman' on macOS — never an "
        + "unpacked download.";

    /// <summary>Refuses with a named prerequisite if <c>ykman</c> is not runnable; returns its version.</summary>
    public string EnsureAvailable()
    {
        try
        {
            var probe = Run(["--version"], echo: false);

            return probe.Succeeded
                ? probe.Output.Trim()
                : throw new InvalidOperationException(
                    $"'{executable} --version' exited {probe.ExitCode}: {probe.All.Trim()}. {InstallHint}");
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or FileNotFoundException)
        {
            // The tool is absent, which is a prerequisite failure rather than a fault: say what is missing
            // and how it is meant to arrive, and stop. Proceeding would produce a series of identical
            // failures naming a slot instead.
            throw new InvalidOperationException(
                $"'{executable}' was not found on PATH, and provisioning a YubiKey needs it: the PIV applet "
                + $"cannot be driven over PKCS#11. {InstallHint}");
        }
    }

    /// <summary>
    /// Runs <c>ykman</c> with <paramref name="arguments"/>, echoing the redacted command and its answer.
    /// </summary>
    /// <param name="echo">
    /// False for the availability probe alone, whose only job is to find out whether the tool exists — a
    /// refusal that has already printed a command line reads as though the command was the problem.
    /// </param>
    public YkmanResult Run(IReadOnlyList<string> arguments, bool echo = true)
    {
        if (echo)
        {
            AnsiConsole.MarkupLine($"[grey]$[/] {Markup.Escape(ArgvRedaction.Of(executable, arguments))}");
        }

        var startInfo = new ProcessStartInfo(executable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"'{executable}' could not be started.");

        // Read BEFORE waiting: a child that fills a pipe blocks on the write while we block on the exit, and
        // `ykman piv info` on a populated token is easily enough output to find that out in production
        // rather than here.
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        var result = new YkmanResult(process.ExitCode, output, error);
        if (echo)
        {
            Echo(result);
        }

        return result;
    }

    /// <summary>
    /// Runs and refuses on a non-zero exit, naming <paramref name="what"/> — for a step with no recovery.
    /// </summary>
    public YkmanResult RunOrThrow(IReadOnlyList<string> arguments, string what)
    {
        var result = Run(arguments);

        return result.Succeeded
            ? result
            : throw new InvalidOperationException(
                $"Could not {what}: '{executable}' exited {result.ExitCode}. {result.All.Trim()}");
    }

    /// <summary>What the tool answered, indented so it reads as a response rather than as more commands.</summary>
    /// <remarks>
    /// The response is part of the record, not decoration: "the command ran" and "the command did what it
    /// says" are different facts, and only the second is worth an administrator's time. ykman writes several
    /// normal messages to stderr, so a non-empty stderr is shown without being called an error — that is
    /// what the exit code is for.
    /// </remarks>
    private static void Echo(YkmanResult result)
    {
        foreach (var line in result.All.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            AnsiConsole.MarkupLine($"[grey]  {Markup.Escape(line.TrimEnd())}[/]");
        }

        if (!result.Succeeded)
        {
            AnsiConsole.MarkupLine($"[yellow]  → exit {result.ExitCode}[/]");
        }
    }
}
