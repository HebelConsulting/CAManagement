using Pkcs11Interop.DataStructures;
using static Pkcs11Interop.DataStructures.CK_ATTRIBUTE_TYPE;
using static Pkcs11Interop.DataStructures.CK_OBJECT_CLASS;

namespace Pkcs11Interop;

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
        string label, NativeULong modulusBits = 2048, byte[]? publicExponent = null)
    {
        using var scope = new NativeAllocationScope();

        var publicTemplate = new[]
        {
            scope.Attribute(CKA_TOKEN, true),
            scope.Attribute(CKA_LABEL, label),
            scope.Attribute(CKA_VERIFY, true),
            scope.Attribute(CKA_MODULUS_BITS, modulusBits),
            scope.Attribute(CKA_PUBLIC_EXPONENT, publicExponent ?? DefaultPublicExponent),
        };

        var privateTemplate = new[]
        {
            scope.Attribute(CKA_TOKEN, true),
            scope.Attribute(CKA_LABEL, label),
            scope.Attribute(CKA_PRIVATE, true),
            scope.Attribute(CKA_SENSITIVE, true),
            scope.Attribute(CKA_SIGN, true),
        };

        var mechanism = new CK_MECHANISM { Mechanism = CK_MECHANISM_TYPE.CKM_RSA_PKCS_KEY_PAIR_GEN };

        return _library.GenerateKeyPair(Handle, mechanism, publicTemplate, privateTemplate);
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
    private static NativeULong ToNativeULong(byte[] value) => value.Length switch
    {
        sizeof(NativeULong) => BitConverter.ToUInt64(value),
        _ => throw new InvalidOperationException($"Expected a {sizeof(NativeULong)}-byte CK_ULONG value but got {value.Length} bytes."),
    };

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
