using CAManagement.Pkcs11.DataStructures;
using static CAManagement.Pkcs11.DataStructures.CK_ATTRIBUTE_TYPE;
using static CAManagement.Pkcs11.DataStructures.CK_OBJECT_CLASS;

namespace CAManagement.Pkcs11;

/// <summary>
/// An open PKCS#11 session. Owns the session handle; disposing closes it
/// (SPEC decision #7). Operations allocate their attribute templates in a
/// <see cref="NativeAllocationScope"/> so native memory is always freed.
/// </summary>
public sealed class Pkcs11Session : IDisposable
{
    private static readonly byte[] DefaultPublicExponent = [0x01, 0x00, 0x01]; // 65537

    private readonly Pkcs11Library _library;

    private bool _disposed;

    public NativeULong Slot { get; }

    public NativeULong Handle { get; }

    internal Pkcs11Session(Pkcs11Library library, NativeULong slot, NativeULong handle)
    {
        _library = library;
        Slot = slot;
        Handle = handle;
    }

    /// <summary>Logs in and returns a scope that logs out when disposed (SPEC #7).</summary>
    public LoginScope Login(string pin, CKU userType = CKU.CKU_USER)
    {
        _library.Login(Handle, userType, System.Text.Encoding.UTF8.GetBytes(pin));
        return new LoginScope(this);
    }

    internal void Logout() => _library.Logout(Handle);

    public (NativeULong publicKey, NativeULong privateKey) GenerateRsaKeyPair(
        string label, NativeULong modulusBits = 2048, byte[]? publicExponent = null,
        byte[]? id = null, Pkcs11KeyPairUsage usage = Pkcs11KeyPairUsage.Signing)
    {
        using var scope = new NativeAllocationScope();

        // Usage flags SWAP with the purpose rather than accumulate: a signing key must not decrypt and an
        // encryption key must not sign — mixed-usage keys are the classic key-hygiene mistake, and the
        // template is where it is prevented. SoftHSM does not enforce these flags (an unflagged key
        // decrypts happily there), so only a strict HSM proves the distinction — which is exactly why the
        // template must be right BEFORE such an HSM is first met.
        var publicUsage = usage == Pkcs11KeyPairUsage.Signing
            ? scope.Attribute(CKA_VERIFY, true)
            : scope.Attribute(CKA_ENCRYPT, true);
        var privateUsage = usage == Pkcs11KeyPairUsage.Signing
            ? scope.Attribute(CKA_SIGN, true)
            : scope.Attribute(CKA_DECRYPT, true);

        var publicTemplate = new List<CK_ATTRIBUTE>
        {
            scope.Attribute(CKA_TOKEN, true),
            scope.Attribute(CKA_LABEL, label),
            publicUsage,
            scope.Attribute(CKA_MODULUS_BITS, modulusBits),
            scope.Attribute(CKA_PUBLIC_EXPONENT, publicExponent ?? DefaultPublicExponent),
        };

        var privateTemplate = new List<CK_ATTRIBUTE>
        {
            scope.Attribute(CKA_TOKEN, true),
            scope.Attribute(CKA_LABEL, label),
            scope.Attribute(CKA_PRIVATE, true),
            scope.Attribute(CKA_SENSITIVE, true),
            privateUsage,
        };

        // CKA_ID on BOTH halves — the PKCS#11 convention the attribute exists for: the halves of one pair
        // (and later its certificate) share the ID. Written whenever the caller supplies one, searched by
        // nobody yet; key GENERATIONS route by versioned label today and the ID is what a future
        // ID-addressed consumer (smart cards) finds already present instead of needing a token backfill.
        if (id is not null)
        {
            publicTemplate.Add(scope.Attribute(CKA_ID, id));
            privateTemplate.Add(scope.Attribute(CKA_ID, id));
        }

        var mechanism = new CK_MECHANISM { Mechanism = CK_MECHANISM_TYPE.CKM_RSA_PKCS_KEY_PAIR_GEN };

        return _library.GenerateKeyPair(Handle, mechanism, [.. publicTemplate], [.. privateTemplate]);
    }

    public (NativeULong publicKey, NativeULong privateKey) GenerateEcKeyPair(
        string label, EllipticCurve curve = EllipticCurve.NistP256)
    {
        using var scope = new NativeAllocationScope();

        var publicTemplate = new[]
        {
            scope.Attribute(CKA_TOKEN, true),
            scope.Attribute(CKA_LABEL, label),
            scope.Attribute(CKA_VERIFY, true),
            scope.Attribute(CKA_EC_PARAMS, curve.EcParams()),
        };

        var privateTemplate = new[]
        {
            scope.Attribute(CKA_TOKEN, true),
            scope.Attribute(CKA_LABEL, label),
            scope.Attribute(CKA_PRIVATE, true),
            scope.Attribute(CKA_SENSITIVE, true),
            scope.Attribute(CKA_SIGN, true),
        };

        var mechanism = new CK_MECHANISM { Mechanism = CK_MECHANISM_TYPE.CKM_EC_KEY_PAIR_GEN };

        return _library.GenerateKeyPair(Handle, mechanism, publicTemplate, privateTemplate);
    }

    /// <summary>Session state and flags (<c>C_GetSessionInfo</c>).</summary>
    public CK_SESSION_INFO GetSessionInfo() => _library.GetSessionInfo(Handle);

    /// <summary>Reads a single attribute's raw value from an object.</summary>
    public byte[] GetAttributeValue(NativeULong objectHandle, CK_ATTRIBUTE_TYPE type) =>
        _library.GetAttributeValue(Handle, objectHandle, type);

    public string GetLabel(NativeULong objectHandle) =>
        System.Text.Encoding.UTF8.GetString(GetAttributeValue(objectHandle, CKA_LABEL));

    public CK_OBJECT_CLASS GetObjectClass(NativeULong objectHandle) =>
        (CK_OBJECT_CLASS)ToNativeULong(GetAttributeValue(objectHandle, CKA_CLASS));

    public CK_KEY_TYPE GetKeyType(NativeULong objectHandle) =>
        (CK_KEY_TYPE)ToNativeULong(GetAttributeValue(objectHandle, CKA_KEY_TYPE));

    // CK_ULONG-valued attributes carry NativeULong-width little-endian bytes.
    private static NativeULong ToNativeULong(byte[] value) => value.Length == sizeof(NativeULong)
        ? System.Runtime.InteropServices.MemoryMarshal.Read<NativeULong>(value)
        : throw new InvalidOperationException($"Expected a {sizeof(NativeULong)}-byte CK_ULONG value but got {value.Length} bytes.");

    public IReadOnlyList<NativeULong> FindObjects(CK_OBJECT_CLASS objectClass, CK_KEY_TYPE keyType)
    {
        using var scope = new NativeAllocationScope();

        var template = new[]
        {
            scope.Attribute(CKA_CLASS, objectClass),
            scope.Attribute(CKA_TOKEN, true),
            scope.Attribute(CKA_KEY_TYPE, keyType),
        };

        return _library.FindObjects(Handle, template);
    }

    public IReadOnlyList<NativeULong> FindObjects(CK_OBJECT_CLASS objectClass, string label)
    {
        using var scope = new NativeAllocationScope();

        var template = new[]
        {
            scope.Attribute(CKA_CLASS, objectClass),
            scope.Attribute(CKA_TOKEN, true),
            scope.Attribute(CKA_LABEL, label),
        };

        return _library.FindObjects(Handle, template);
    }

    /// <summary>
    /// Imports a DER-encoded X.509 certificate as a token object. The DER subject
    /// name is passed in by the caller — parsing certificates is the concern of
    /// the (future) ASN.1/CA library, not of this PKCS#11 layer.
    /// </summary>
    public NativeULong ImportX509Certificate(string label, byte[] certificateDer, byte[] subjectDer, byte[]? id = null)
    {
        using var scope = new NativeAllocationScope();

        var template = new List<CK_ATTRIBUTE>
        {
            scope.Attribute(CKA_CLASS, CKO_CERTIFICATE),
            scope.Attribute(CKA_CERTIFICATE_TYPE, CK_CERTIFICATE_TYPE.CKC_X_509),
            scope.Attribute(CKA_TOKEN, true),
            scope.Attribute(CKA_LABEL, label),
            scope.Attribute(CKA_VALUE, certificateDer),
            scope.Attribute(CKA_SUBJECT, subjectDer),
        };

        if (id is not null)
        {
            template.Add(scope.Attribute(CKA_ID, id));
        }

        return _library.CreateObject(Handle, template.ToArray());
    }

    /// <summary>Stores an opaque data object on the token (e.g. CA state like a CRL number).</summary>
    public NativeULong CreateDataObject(string label, byte[] value)
    {
        using var scope = new NativeAllocationScope();

        var template = new[]
        {
            scope.Attribute(CKA_CLASS, CKO_DATA),
            scope.Attribute(CKA_TOKEN, true),
            scope.Attribute(CKA_LABEL, label),
            scope.Attribute(CKA_VALUE, value),
        };

        return _library.CreateObject(Handle, template);
    }

    public void DestroyObject(NativeULong objectHandle) => _library.DestroyObject(Handle, objectHandle);

    /// <summary>Replaces an attribute value in place (<c>C_SetAttributeValue</c>), e.g. a data object's CKA_VALUE.</summary>
    public void SetAttributeValue(NativeULong objectHandle, CK_ATTRIBUTE_TYPE type, byte[] value)
    {
        using var scope = new NativeAllocationScope();

        _library.SetAttributeValue(Handle, objectHandle, [scope.Attribute(type, value)]);
    }

    /// <summary>Signs <paramref name="data"/> with the given private key handle.</summary>
    public byte[] Sign(CK_MECHANISM_TYPE mechanismType, byte[] data, NativeULong privateKeyHandle)
    {
        _library.SignInit(Handle, new CK_MECHANISM { Mechanism = mechanismType }, privateKeyHandle);

        return _library.Sign(Handle, data);
    }

    /// <summary>Signs using the token's single RSA/EC private key (convenience overload).</summary>
    public byte[] Sign(CK_MECHANISM_TYPE mechanismType, byte[] data) =>
        Sign(mechanismType, data, SingleObject(FindObjects(CKO_PRIVATE_KEY, Mechanisms.KeyTypeFor(mechanismType))));

    /// <summary>Verifies <paramref name="signature"/> with the given public key handle.</summary>
    public bool Verify(CK_MECHANISM_TYPE mechanismType, byte[] data, byte[] signature, NativeULong publicKeyHandle)
    {
        _library.VerifyInit(Handle, new CK_MECHANISM { Mechanism = mechanismType }, publicKeyHandle);

        return _library.Verify(Handle, data, signature);
    }

    /// <summary>Verifies using the token's single RSA/EC public key (convenience overload).</summary>
    public bool Verify(CK_MECHANISM_TYPE mechanismType, byte[] data, byte[] signature) =>
        Verify(mechanismType, data, signature, SingleObject(FindObjects(CKO_PUBLIC_KEY, Mechanisms.KeyTypeFor(mechanismType))));

    /// <summary>Encrypts <paramref name="data"/> with the given key handle and a parameterless mechanism.</summary>
    public byte[] Encrypt(CK_MECHANISM_TYPE mechanismType, byte[] data, NativeULong keyHandle)
    {
        _library.EncryptInit(Handle, new CK_MECHANISM { Mechanism = mechanismType }, keyHandle);

        return _library.Encrypt(Handle, data);
    }

    /// <summary>Decrypts <paramref name="data"/> with the given key handle and a parameterless mechanism.</summary>
    public byte[] Decrypt(CK_MECHANISM_TYPE mechanismType, byte[] data, NativeULong keyHandle)
    {
        _library.DecryptInit(Handle, new CK_MECHANISM { Mechanism = mechanismType }, keyHandle);

        return _library.Decrypt(Handle, data);
    }

    /// <summary>Encrypts under RSA-OAEP with the given public key — the wrap half of envelope encryption,
    /// present mostly so the two directions can be round-tripped against one token in tests; a consumer
    /// holding the public key can (and normally should) wrap in software without a token round-trip.</summary>
    public byte[] EncryptRsaOaep(byte[] data, NativeULong publicKeyHandle,
        CK_MECHANISM_TYPE hashAlgorithm = CK_MECHANISM_TYPE.CKM_SHA256)
    {
        using var scope = new NativeAllocationScope();

        _library.EncryptInit(Handle, OaepMechanism(scope, hashAlgorithm), publicKeyHandle);

        return _library.Encrypt(Handle, data);
    }

    /// <summary>
    /// Decrypts under RSA-OAEP with the given private key — the UNWRAP half of envelope encryption, and the
    /// reason encrypt/decrypt exist here at all: a consumer wraps a small data key in software against the
    /// token key's public half, and this is the only operation that needs the token. The hash defaults to
    /// SHA-256 to match .NET's <c>RSAEncryptionPadding.OaepSHA256</c> (MGF1 pairs automatically, RFC 8017).
    /// </summary>
    public byte[] DecryptRsaOaep(byte[] data, NativeULong privateKeyHandle,
        CK_MECHANISM_TYPE hashAlgorithm = CK_MECHANISM_TYPE.CKM_SHA256)
    {
        using var scope = new NativeAllocationScope();

        _library.DecryptInit(Handle, OaepMechanism(scope, hashAlgorithm), privateKeyHandle);

        return _library.Decrypt(Handle, data);
    }

    /// <summary>Builds the OAEP mechanism; the parameter block lives in <paramref name="scope"/>, which must
    /// outlive the whole init+operate pair — the module may read it on either call.</summary>
    private static CK_MECHANISM OaepMechanism(NativeAllocationScope scope, CK_MECHANISM_TYPE hashAlgorithm)
    {
        var parameters = new CK_RSA_PKCS_OAEP_PARAMS
        {
            HashAlgorithm = hashAlgorithm,
            Mgf = Mechanisms.Mgf1For(hashAlgorithm),
            Source = CK_RSA_PKCS_OAEP_SOURCE_TYPE.CKZ_DATA_SPECIFIED,
            SourceData = IntPtr.Zero,
            SourceDataLength = 0,
        };

        return new CK_MECHANISM
        {
            Mechanism = CK_MECHANISM_TYPE.CKM_RSA_PKCS_OAEP,
            Parameter = scope.Allocate(in parameters),
            ParameterLength = (NativeULong)System.Runtime.InteropServices.Marshal.SizeOf<CK_RSA_PKCS_OAEP_PARAMS>(),
        };
    }

    /// <summary>
    /// Signs a stream of parts (<c>C_SignInit</c> / <c>C_SignUpdate…</c> /
    /// <c>C_SignFinal</c>) — for data too large to hold in one buffer. The
    /// mechanism must be a multi-part one (a hashing mechanism such as
    /// <c>CKM_SHA256_RSA_PKCS</c>, not raw <c>CKM_RSA_PKCS</c>).
    /// </summary>
    public byte[] SignParts(CK_MECHANISM_TYPE mechanismType, IEnumerable<byte[]> parts, NativeULong privateKeyHandle)
    {
        _library.SignInit(Handle, new CK_MECHANISM { Mechanism = mechanismType }, privateKeyHandle);

        foreach (var part in parts)
        {
            _library.SignUpdate(Handle, part);
        }

        return _library.SignFinal(Handle);
    }

    /// <summary>Verifies a stream of parts (<c>C_VerifyInit</c> / <c>C_VerifyUpdate…</c> / <c>C_VerifyFinal</c>).</summary>
    public bool VerifyParts(CK_MECHANISM_TYPE mechanismType, IEnumerable<byte[]> parts, byte[] signature, NativeULong publicKeyHandle)
    {
        _library.VerifyInit(Handle, new CK_MECHANISM { Mechanism = mechanismType }, publicKeyHandle);

        foreach (var part in parts)
        {
            _library.VerifyUpdate(Handle, part);
        }

        return _library.VerifyFinal(Handle, signature);
    }

    /// <summary>Sets the user PIN on a token from an SO session (<c>C_InitPIN</c>).</summary>
    public void InitializeUserPin(string userPin) =>
        _library.InitPin(Handle, System.Text.Encoding.UTF8.GetBytes(userPin));

    /// <summary>Changes the PIN of the logged-in user, or the user PIN from an R/W public session (<c>C_SetPIN</c>).</summary>
    public void SetPin(string oldPin, string newPin) =>
        _library.SetPin(Handle, System.Text.Encoding.UTF8.GetBytes(oldPin), System.Text.Encoding.UTF8.GetBytes(newPin));

    private static NativeULong SingleObject(IReadOnlyList<NativeULong> handles) => handles.Count switch
    {
        1 => handles[0],
        0 => throw new InvalidOperationException("No matching object was found on the token."),
        _ => throw new InvalidOperationException($"Expected exactly one matching object but found {handles.Count}."),
    };

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _library.CloseSession(Handle);
    }
}
