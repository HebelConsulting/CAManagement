namespace CAManagement.X509;

/// <summary>What a leaf certificate is FOR — the caller states this, and the bits are derived (#18).</summary>
/// <remarks>
/// A profile rather than a list of keyUsage bits, because naming the bits is how the defect this exists to
/// fix was written in the first place: a certificate issued for a YubiKey's Key Management slot carried
/// <c>digitalSignature</c>, which is the one bit that does not apply to it. Stating the purpose makes the
/// wrong bit unwritable; stating the bits makes it available.
/// </remarks>
public enum CertificateProfile
{
    /// <summary>A signing certificate: <c>digitalSignature</c>, no extended key usage. The default, unchanged.</summary>
    Signing = 0,

    /// <summary>
    /// A DECRYPTION certificate — the recipient of CMS <c>EnvelopedData</c>, and what a PIV Key Management
    /// slot (9D) holds.
    /// </summary>
    KeyManagement = 1,
}

/// <summary>The extensions a <see cref="CertificateProfile"/> implies for a particular public key.</summary>
/// <remarks>
/// <para>
/// <b>Why this is derived and not configured (#18).</b> The relevant keyUsage bit for a decryption
/// certificate is a property of the KEY ALGORITHM, not of anybody's preference: RSA is key *transport* and
/// takes <c>keyEncipherment</c>; EC is key *agreement* (ECDH) and takes <c>keyAgreement</c>. Get it wrong and
/// the certificate still works — measured on hardware, a <c>digitalSignature</c>-only certificate decrypted a
/// real CMS envelope, because neither <c>EnvelopedCms</c> nor the token enforces keyUsage. It fails only
/// against consumers that CHECK, which is the reasonable thing to do, and then it fails as a
/// wrong-looking decryption error naming nothing.
/// </para>
/// <para>
/// So the caller says <c>key-management</c> and this answers with the bit that key can actually honour.
/// SimplArchive's enrolment refuses a signature-only certificate outright — <i>"enrolling it would address
/// documents to a key that can never read them"</i> — so the derivation is what makes a provisioned card
/// enrollable rather than something that has to be re-issued afterwards.
/// </para>
/// <para>
/// A pure function over the SPKI's algorithm OID, so it is asserted directly rather than inferred from an
/// issued certificate: the wrong answer here is invisible in every test that only checks a certificate parses.
/// </para>
/// </remarks>
public sealed record CertificatePurpose(KeyUsages KeyUsage, IReadOnlyList<string> ExtendedKeyUsages)
{
    /// <summary>
    /// The purpose for <paramref name="profile"/> over a key of <paramref name="publicKeyAlgorithmOid"/>.
    /// </summary>
    /// <exception cref="NotSupportedException">
    /// The key algorithm cannot serve the profile. Deliberately a refusal rather than a fall-back to
    /// <see cref="CertificateProfile.Signing"/>: issuing a signing certificate for a decryption slot is
    /// exactly the outcome being prevented, and it would arrive looking like a success.
    /// </exception>
    public static CertificatePurpose For(CertificateProfile profile, string publicKeyAlgorithmOid) =>
        profile switch
        {
            // Unchanged from before the profile existed, and no extended key usage: an absent EKU means "any
            // purpose", which is what every certificate this tool has already issued relies on.
            CertificateProfile.Signing => new CertificatePurpose(KeyUsages.DigitalSignature, []),

            CertificateProfile.KeyManagement => publicKeyAlgorithmOid switch
            {
                // ECDH. `keyAgreement` is also why such a certificate CANNOT be self-signed — .NET refuses to
                // sign with a key declared for agreement — which is not a limitation but the reason a CA is in
                // this flow at all.
                Oids.EcPublicKey => new CertificatePurpose(
                    KeyUsages.KeyAgreement, [Oids.EmailProtection]),

                // RSA key transport (CKM_RSA_PKCS in the CMS sense).
                Oids.RsaEncryption => new CertificatePurpose(
                    KeyUsages.KeyEncipherment, [Oids.EmailProtection]),

                _ => throw new NotSupportedException(
                    $"A {nameof(CertificateProfile.KeyManagement)} certificate needs a key that can either "
                    + $"agree or transport a content key; the request's key algorithm is {publicKeyAlgorithmOid}, "
                    + "which does neither. Issuing a signing certificate instead would produce one that "
                    + "decrypts nothing and is refused where keyUsage is checked."),
            },

            _ => throw new NotSupportedException($"Unknown certificate profile '{profile}'."),
        };

    /// <summary>The CLI spelling — kebab-case, as an option value is written.</summary>
    /// <remarks>
    /// Parsed here rather than by the argument binder's enum conversion, which would accept
    /// <c>KeyManagement</c> and reject <c>key-management</c>: the hyphenated form is how every other option
    /// value in this tool reads, and a refusal that lists the accepted values is more use than one that
    /// names a CLR type.
    /// </remarks>
    public static CertificateProfile Parse(string value) => value.Trim().ToLowerInvariant() switch
    {
        "signing" => CertificateProfile.Signing,
        "key-management" or "keymanagement" => CertificateProfile.KeyManagement,
        _ => throw new ArgumentException(
            $"'{value}' is not a certificate profile. Use 'signing' (digitalSignature, the default) or "
            + "'key-management' (a decryption certificate: keyAgreement for EC, keyEncipherment for RSA, "
            + "with emailProtection).", nameof(value)),
    };
}
