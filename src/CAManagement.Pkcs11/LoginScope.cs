namespace CAManagement.Pkcs11;

/// <summary>
/// Represents an active login on a <see cref="Pkcs11Session"/>. Disposing logs
/// the user out (SPEC decision #7). Obtain one via <see cref="Pkcs11Session.Login"/>.
/// </summary>
public sealed class LoginScope : IDisposable
{
    private readonly Pkcs11Session _session;

    private bool _disposed;

    internal LoginScope(Pkcs11Session session) => _session = session;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _session.Logout();
    }
}
