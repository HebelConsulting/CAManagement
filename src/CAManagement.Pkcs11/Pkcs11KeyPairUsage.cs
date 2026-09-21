namespace CAManagement.Pkcs11;

/// <summary>
/// What a generated key pair is FOR — which decides its usage flags, because the flags must swap with the
/// purpose rather than accumulate: a signing key must not decrypt, an encryption key must not sign.
/// </summary>
/// <remarks>
/// Exactly the two purposes with a concrete consumer today (the CA's signing keys; SimplArchiveEncryption's
/// KEK generations). SoftHSM does not enforce usage flags, so the distinction only bites on a strict HSM —
/// which is why the template carries it now rather than after the first such HSM refuses a
/// <c>C_DecryptInit</c> with <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>.
/// </remarks>
public enum Pkcs11KeyPairUsage
{
    /// <summary>Sign/verify — the CA case, and the default (the pre-existing template's behaviour).</summary>
    Signing = 0,

    /// <summary>Encrypt/decrypt — the envelope-encryption KEK case (issue #1).</summary>
    Encryption = 1,
}
