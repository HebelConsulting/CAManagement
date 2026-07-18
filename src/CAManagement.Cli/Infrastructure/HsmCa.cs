using CAManagement.X509;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Signing;
using Spectre.Console;

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

    public Pkcs11Session OpenLoggedInSession(HsmSettings settings)
    {
        _library = new Pkcs11Library(settings.ToPkcs11Options());
        _session = _library.OpenSession();

        var pin = settings.Pin
            ?? AnsiConsole.Prompt(new TextPrompt<string>("User PIN:").Secret());
        _login = _session.Login(pin);

        return _session;
    }

    /// <summary>Finds the CA key pair by label and builds the matching signer + SPKI.</summary>
    public (Pkcs11CertificateSigner Signer, SubjectPublicKeyInfo Spki) LoadCaKey(Pkcs11Session session, string label)
    {
        var privateKey = SingleHandle(session.FindObjects(CK_OBJECT_CLASS.CKO_PRIVATE_KEY, label), label, "private");
        var publicKey = SingleHandle(session.FindObjects(CK_OBJECT_CLASS.CKO_PUBLIC_KEY, label), label, "public");

        var algorithm = session.GetKeyType(privateKey) switch
        {
            CK_KEY_TYPE.CKK_RSA => SignatureAlgorithm.Sha256WithRsa,
            CK_KEY_TYPE.CKK_ECDSA => SignatureAlgorithm.EcdsaWithSha256,
            var keyType => throw new NotSupportedException($"Unsupported CA key type {keyType}."),
        };

        return (new Pkcs11CertificateSigner(session, privateKey, algorithm), Pkcs11PublicKeyReader.Read(session, publicKey));
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
