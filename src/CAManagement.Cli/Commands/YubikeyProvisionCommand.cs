using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using CAManagement.Cli.Infrastructure;
using CAManagement.X509;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAManagement.Cli.Commands;

/// <summary>
/// Prepares a YubiKey for SimplArchive end to end: a key in the Key Management slot, a CSR the CARD signs,
/// a certificate this CA issues for decryption, and the certificate imported back (#21).
/// </summary>
/// <remarks>
/// <para>
/// <b>ECDH over RSA</b>, because that is the best method SimplArchive supports (owner, 2026-09-30). The
/// consequence rides through the whole flow: an EC key means the certificate's keyUsage must be
/// <c>keyAgreement</c>, which is derived from the key rather than chosen (<see cref="CertificatePurpose"/>,
/// #18) — a <c>digitalSignature</c>-only certificate is refused by SimplArchive's enrolment, correctly,
/// because <i>enrolling it would address documents to a key that can never read them</i>.
/// </para>
/// <para>
/// <b>The CSR is signed by the card</b>, and that is not ceremony: it is the only proof available that the
/// private key is live and reachable, on a platform where the applet may decline to say whether a key exists
/// at all. A <c>keyAgreement</c> certificate cannot be self-signed — .NET refuses to sign with a key declared
/// for agreement — which is why the CA is in this flow rather than an optional extra.
/// </para>
/// <para>
/// <b>Destructive by request only.</b> Re-issuing a certificate for an existing key is non-destructive: only
/// <c>keys generate</c> destroys a key, so the default path for an occupied slot REPLACES THE CERTIFICATE and
/// keeps the key — which is exactly the repair a card carrying a wrong-usage certificate needs.
/// <c>--regenerate-key</c> is the separate, explicit opt-in to destroying it.
/// </para>
/// </remarks>
public sealed class YubikeyProvisionCommand : Command<YubikeyProvisionCommand.Settings>
{
    public sealed class Settings : HsmLoginSettings
    {
        [CommandOption("--holder <EMAIL>")]
        [Description("Who the certificate is for; becomes the subject CN and the manifest's address.")]
        public required string Holder { get; init; }

        [CommandOption("--ca-label <LABEL>")]
        [Description("Token label of the CA key pair that signs the certificate.")]
        public required string CaLabel { get; init; }

        [CommandOption("--ca-cert <FILE>")]
        [Description("The CA certificate (PEM or DER); its subject becomes the issuer.")]
        public required string CaCert { get; init; }

        // NOT --slot: HsmSettings already owns that for the CA TOKEN's PKCS#11 slot, and two different
        // meanings behind one option name is how somebody re-keys a card while meaning to pick a token.
        [CommandOption("--card-slot <SLOT>")]
        [Description("PIV slot on the card. Default 9d (Key Management) — the decryption slot.")]
        [DefaultValue("9d")]
        public string CardSlot { get; init; } = "9d";

        [CommandOption("--algorithm <ALGORITHM>")]
        [Description("Key algorithm for a NEW key, as ykman spells it. Default ECCP256 (ECDH, preferred).")]
        [DefaultValue("ECCP256")]
        public string Algorithm { get; init; } = "ECCP256";

        [CommandOption("-P|--card-pin <PIN>")]
        [Description("The card's PIV PIN. Prompted by ykman when omitted.")]
        public string? CardPin { get; init; }

        [CommandOption("-m|--management-key <KEY>")]
        [Description("The card's PIV management key. Prompted by ykman when omitted.")]
        public string? ManagementKey { get; init; }

        [CommandOption("--days <DAYS>")]
        [DefaultValue(365)]
        public int Days { get; init; } = 365;

        [CommandOption("--label <LABEL>")]
        [Description("What the holder calls this key, for the manifest: \"YubiKey 5C\". Defaults to the card.")]
        public string? Label { get; init; }

        [CommandOption("--manifest <FILE>")]
        [Description("Record the issuance in this enrolment manifest, for SimplArchive's bulk import. "
            + "Created if absent; a row with the same serial is replaced.")]
        public string? Manifest { get; init; }

        [CommandOption("--out-dir <DIR>")]
        [Description("Where the CSR, the issued certificate and any exported predecessor are written.")]
        [DefaultValue(".")]
        public string OutDir { get; init; } = ".";

        [CommandOption("--force")]
        [Description("Replace the certificate in an occupied slot. Keeps the private key.")]
        public bool Force { get; init; }

        [CommandOption("--regenerate-key")]
        [Description("DESTROY the slot's private key and generate a new one. Irreversible.")]
        public bool RegenerateKey { get; init; }

        public override ValidationResult Validate() => string.IsNullOrWhiteSpace(Holder)
            ? ValidationResult.Error("Missing required option --holder.")
            : base.Validate();
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var ykman = new YkmanTool();
        AnsiConsole.MarkupLine($"[grey]ykman[/] {Markup.Escape(ykman.EnsureAvailable())}");

        var slot = settings.CardSlot.ToLowerInvariant();
        var state = PivInfo.Read(ykman.RunOrThrow(["piv", "info"], "read the card's PIV state").All, slot);
        AnsiConsole.MarkupLine($"[blue]Card:[/] {Markup.Escape(PivInfo.Describe(state))}");

        if (Refuse(state, settings) is { } refusal)
        {
            AnsiConsole.MarkupLine($"[yellow]Refused:[/] {Markup.Escape(refusal)}");
            return 1;
        }

        Directory.CreateDirectory(settings.OutDir);
        var stem = Path.Combine(settings.OutDir, $"{SafeName(settings.Holder)}-{slot}");

        // THE PREDECESSOR FIRST, always, before anything can replace it. An identity artefact is one-shot:
        // the copy on the card is usually the only copy, and a certificate that is about to be overwritten
        // is still the only record of what that key was addressed as.
        if (state.HasCertificate)
        {
            var exported = $"{stem}-previous.crt";
            if (ykman.Run(["piv", "certificates", "export", slot, exported]).Succeeded)
            {
                AnsiConsole.MarkupLine($"[grey]Kept the previous certificate at[/] [blue]{Markup.Escape(exported)}[/].");
            }
        }

        var publicKeyFile = $"{stem}-public.pem";
        if (settings.RegenerateKey || state.KeyPresence == KeyPresence.Absent)
        {
            // The one irreversible step, and the only one that needs the management key.
            ykman.RunOrThrow(
                [.. Credentials(settings), "piv", "keys", "generate", "-a", settings.Algorithm, slot, publicKeyFile],
                $"generate a {settings.Algorithm} key in slot {slot}");
        }
        else
        {
            // KEEPING the key — the non-destructive repair. Exporting its public half is what lets a CSR be
            // built for a key that already exists; where the applet will not export it, say so rather than
            // quietly re-keying.
            var export = ykman.Run(["piv", "keys", "export", slot, publicKeyFile]);
            if (!export.Succeeded)
            {
                AnsiConsole.MarkupLine(
                    "[yellow]Refused:[/] the card would not export the existing public key in slot "
                    + $"{Markup.Escape(slot)}, so a request cannot be built for the key that is already there. "
                    + "Re-run with [blue]--regenerate-key[/] to replace the key — which DESTROYS it — or use a "
                    + "card whose applet reports key metadata (firmware 5.3 or newer).");
                return 1;
            }
        }

        // THE CARD SIGNS ITS OWN REQUEST: proof the private key is live, which is the only such proof
        // available on an applet that may decline to say whether a key exists.
        var csrFile = $"{stem}.csr";
        ykman.RunOrThrow(
            [.. Credentials(settings, managementKey: false),
             "piv", "certificates", "request", slot, publicKeyFile, csrFile,
             "-s", $"CN={settings.Holder}"],
            $"have the card sign a certificate request for slot {slot}");

        var certificateFile = $"{stem}.crt";
        var issued = Issue(settings, csrFile, certificateFile);

        ykman.RunOrThrow(
            [.. Credentials(settings), "piv", "certificates", "import", slot, certificateFile],
            $"import the issued certificate into slot {slot}");

        // THE MANIFEST LAST, and only once the card actually holds the certificate: it is a record of what
        // was handed over, so writing it before the import would promise an enrolment that may not have
        // happened. `RunOrThrow` above is what makes "we got here" mean "the card took it".
        if (settings.Manifest is { Length: > 0 } manifestPath)
        {
            var manifest = EnrolmentManifest.Read(manifestPath);
            manifest.RecordIssued(
                settings.Holder,
                settings.Label ?? $"YubiKey slot {slot}",
                issued);
            manifest.Write(manifestPath);
            AnsiConsole.MarkupLine($"[grey]Recorded in[/] [blue]{Markup.Escape(manifestPath)}[/].");
        }

        // READ BACK, because "the command exited zero" and "the card now holds this" are different facts,
        // and only the second is what was asked for.
        var after = PivInfo.Read(ykman.RunOrThrow(["piv", "info"], "re-read the card's PIV state").All, slot);
        AnsiConsole.MarkupLine($"[green]Provisioned[/] {Markup.Escape(PivInfo.Describe(after))}");
        AnsiConsole.MarkupLine(
            $"  holder [blue]{Markup.Escape(settings.Holder)}[/], serial [yellow]{issued.SerialNumber}[/], "
            + $"keyUsage [yellow]{issued.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault()?.KeyUsages}[/], "
            + $"certificate [blue]{Markup.Escape(certificateFile)}[/]");

        return 0;
    }

    /// <summary>Why this card must not be touched yet, or null to proceed.</summary>
    /// <remarks>
    /// The owner's refinement (2026-09-30): where something is already in the slot, <b>print what is there</b>
    /// and say which flag to re-run with. A refusal that does not name the occupant leaves the operator to
    /// find out by overwriting it.
    /// </remarks>
    private static string? Refuse(PivSlotState state, Settings settings)
    {
        if (settings is { Force: false, RegenerateKey: false }
            && (state.HasCertificate || !state.SafeToGenerateWithoutForce))
        {
            return $"{PivInfo.Describe(state)}. Re-run with [blue]--force[/] to replace the certificate and "
                + "KEEP the key (the repair for a certificate with the wrong key usage), or "
                + "[blue]--regenerate-key[/] to replace the key as well — which destroys it, and anything "
                + "encrypted to it becomes unreadable.";
        }

        return null;
    }

    /// <summary>
    /// Issues the decryption certificate from the card's own request, signed by the token-resident CA key.
    /// </summary>
    /// <remarks>
    /// In-process rather than by shelling out to this tool's own <c>issue</c> command: the CA PIN would
    /// otherwise cross a process boundary on argv, and one flow that can fail halfway is easier to reason
    /// about than two.
    /// </remarks>
    private static X509Certificate2 Issue(Settings settings, string csrFile, string outFile)
    {
        using var hsm = new HsmCa();
        var session = hsm.OpenLoggedInSession(settings, settings.Pin);
        var (signer, caSpki) = hsm.LoadCaKey(session, settings.CaLabel);

        var issuer = X509Names.SubjectOf(File.ReadAllBytes(settings.CaCert));
        var csr = CertificateSigningRequest.Decode(IssueCommand.ReadDer(csrFile)); // verifies proof of possession

        // THE WHOLE POINT OF #18: the usage follows the KEY. An EC key agrees, an RSA key transports, and
        // the caller does not get to name the bit.
        var purpose = CertificatePurpose.For(CertificateProfile.KeyManagement, csr.SubjectPublicKeyInfo.AlgorithmOid);

        var der = new CertificateBuilder
        {
            Subject = csr.Subject,
            SubjectPublicKeyInfo = csr.SubjectPublicKeyInfo,
            NotBefore = DateTimeOffset.UtcNow.AddHours(-1),
            NotAfter = DateTimeOffset.UtcNow.AddDays(settings.Days),
            Extensions =
            [
                CertificateExtensions.BasicConstraints(isCa: false),
                CertificateExtensions.KeyUsage(purpose.KeyUsage),
                CertificateExtensions.ExtendedKeyUsage([.. purpose.ExtendedKeyUsages]),
                CertificateExtensions.SubjectKeyIdentifier(csr.SubjectPublicKeyInfo.ComputeKeyIdentifier()),
                CertificateExtensions.AuthorityKeyIdentifier(caSpki.ComputeKeyIdentifier()),
                .. csr.RequestedExtensions.Where(e => e.Oid == Oids.SubjectAlternativeName),
            ],
        }.Sign(issuer, signer);

        File.WriteAllText(outFile, Pem.Encode("CERTIFICATE", der));

        return X509CertificateLoader.LoadCertificate(der);
    }

    /// <summary>
    /// The card credentials as ykman options — omitted entirely when not given, so ykman prompts.
    /// </summary>
    /// <remarks>
    /// Passing them is a convenience for a scripted enrolment; leaving them out is the better default for a
    /// human, because a PIN typed at a prompt does not reach the shell's history. Whichever way they arrive,
    /// the echoed command line redacts them by option NAME (<see cref="ArgvRedaction"/>).
    /// </remarks>
    private static List<string> Credentials(Settings settings, bool managementKey = true)
    {
        var options = new List<string>();
        if (settings.CardPin is { Length: > 0 } pin)
        {
            options.AddRange(["-P", pin]);
        }

        if (managementKey && settings.ManagementKey is { Length: > 0 } key)
        {
            options.AddRange(["-m", key]);
        }

        return options;
    }

    /// <summary>A filename stem from an address, so two holders' artefacts cannot collide or escape the directory.</summary>
    private static string SafeName(string holder) =>
        new([.. holder.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_')]);
}
