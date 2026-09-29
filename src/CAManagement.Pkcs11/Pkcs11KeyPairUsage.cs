namespace CAManagement.Pkcs11;

/// <summary>
/// What a generated key pair is FOR — which decides its usage flags, because the flags must swap with the
/// purpose rather than accumulate: a signing key must not decrypt, an encryption key must not sign.
/// </summary>
/// <remarks>
/// The purposes with a concrete consumer today: the CA's signing keys, SimplArchiveEncryption's KEK
/// generations, and — since <see cref="Pkcs11Session.DeriveEcdhSecret"/> — an elliptic-curve recipient's
/// agreement key.
///
/// <para>
/// <b>An earlier version of this remark said SoftHSM does not enforce usage flags. That is false for
/// derivation.</b> This note predicted a strict HSM would one day refuse with
/// <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>; SoftHSM 2.7.0 refuses <c>C_DeriveKey</c> against a key generated
/// without <c>CKA_DERIVE</c> immediately, which is how <see cref="KeyAgreement"/> came to exist. So the
/// swap-rather-than-accumulate rule is enforced by the development token too, and the flags cannot be
/// treated as documentation.
/// </para>
/// </remarks>
public enum Pkcs11KeyPairUsage
{
    /// <summary>Sign/verify — the CA case, and the default (the pre-existing template's behaviour).</summary>
    Signing = 0,

    /// <summary>Encrypt/decrypt — the envelope-encryption KEK case (issue #1).</summary>
    Encryption = 1,

    /// <summary>
    /// Derive — an elliptic-curve key used for ECDH agreement, where a CMS recipient's content key is AGREED
    /// rather than wrapped.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="Encryption"/> because the flags genuinely differ: an agreement key carries
    /// <c>CKA_DERIVE</c> and neither <c>CKA_DECRYPT</c> nor <c>CKA_SIGN</c>. Folding it into Encryption would
    /// hand an EC key a decrypt flag it can never honour — EC has no key transport — and hide the one flag it
    /// actually needs.
    /// </remarks>
    KeyAgreement = 2,
}
