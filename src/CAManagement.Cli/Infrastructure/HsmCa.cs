using CAManagement.X509;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Signing;

namespace CAManagement.Cli.Infrastructure;

/// <summary>
/// Shared HSM plumbing for the CA commands: module loading, session, login and
/// key lookup, driven entirely by <see cref="HsmSettings"/> CLI options.
/// </summary>
public sealed class HsmCa : IDisposable
{
    private Pkcs11Library? _library;
    private Pkcs11Session? _session;
    private LoginScope? _login;

    public Pkcs11Session OpenLoggedInSession(HsmSettings settings, string pin)
    {
        _library = new Pkcs11Library(settings.ToPkcs11Options());
        _session = _library.OpenSession();
        _login = _session.Login(pin);

        return _session;
    }

    /// <summary>Finds the CA key pair by label and builds the matching signer + SPKI.</summary>
    public (Pkcs11CertificateSigner Signer, SubjectPublicKeyInfo Spki) LoadCaKey(Pkcs11Session session, string label)
    {
        var privateKey = SingleHandle(session.FindObjects(CK_OBJECT_CLASS.CKO_PRIVATE_KEY, label), label, "private");
        var publicKey = SingleHandle(session.FindObjects(CK_OBJECT_CLASS.CKO_PUBLIC_KEY, label), label, "public");

        // The algorithm derivation moved into the signer itself (issue #9) so every consumer gets it,
        // not just the CLI — the identity tooling that hardcoded RSA is exactly who this was for.
        return (Pkcs11CertificateSigner.ForKey(session, privateKey), Pkcs11PublicKeyReader.Read(session, publicKey));
    }

    private static NativeULong SingleHandle(IReadOnlyList<NativeULong> handles, string label, string kind) => handles.Count switch
    {
        1 => handles[0],
        0 => throw new InvalidOperationException($"No {kind} key with label '{label}' found on the token."),
        _ => throw new InvalidOperationException($"Multiple {kind} keys with label '{label}' found on the token."),
    };

    public void Dispose()
    {
        _login?.Dispose();
        _session?.Dispose();
        _library?.Dispose();
    }
}
