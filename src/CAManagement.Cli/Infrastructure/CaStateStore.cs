using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;

namespace CAManagement.Cli.Infrastructure;

public interface ICaStateStore
{
    CaStateFile Load();

    void Save(CaStateFile state);
}

public sealed class FileCaStateStore(string path) : ICaStateStore
{
    public CaStateFile Load() => CaStateFile.Load(path);

    public void Save(CaStateFile state) => state.Save(path);
}

/// <summary>
/// Keeps the CA state as a CKO_DATA object on the token (label
/// "ca-state:&lt;ca-label&gt;"), so it lives and travels with the CA key and is
/// only reachable after login.
///
/// SoftHSM refuses in-place CKA_VALUE updates (CKR_ATTRIBUTE_READ_ONLY), but
/// allows CKA_LABEL updates — so Save uses a staged rename: create the new
/// state under a staging label, destroy the old object, rename the staged one
/// to the final label. Every crash window leaves either the old state (final
/// label) or the new state (staging label, healed by the next Load).
/// </summary>
public sealed class TokenCaStateStore(Pkcs11Session session, string caLabel) : ICaStateStore
{
    private string Label => $"ca-state:{caLabel}";

    private string StagingLabel => $"{Label}.new";

    public CaStateFile Load()
    {
        var handle = FindSingle(Label) ?? HealFromStaging();

        return handle is { } stateObject
            ? CaStateFile.FromJson(session.GetAttributeValue(stateObject, CK_ATTRIBUTE_TYPE.CKA_VALUE))
            : new CaStateFile();
    }

    public void Save(CaStateFile state)
    {
        // Leftover staging objects from a crashed Save are superseded by this one.
        foreach (var stale in session.FindObjects(CK_OBJECT_CLASS.CKO_DATA, StagingLabel))
        {
            session.DestroyObject(stale);
        }

        var staged = session.CreateDataObject(StagingLabel, state.ToJson());

        if (FindSingle(Label) is { } previous)
        {
            session.DestroyObject(previous);
        }

        Rename(staged, Label);
    }

    /// <summary>A Save crashed between destroy and rename — adopt the staged state.</summary>
    private NativeULong? HealFromStaging()
    {
        if (FindSingle(StagingLabel) is not { } staged)
        {
            return null;
        }

        Rename(staged, Label);

        return staged;
    }

    private void Rename(NativeULong handle, string label) =>
        session.SetAttributeValue(handle, CK_ATTRIBUTE_TYPE.CKA_LABEL, System.Text.Encoding.UTF8.GetBytes(label));

    private NativeULong? FindSingle(string label)
    {
        var handles = session.FindObjects(CK_OBJECT_CLASS.CKO_DATA, label);

        return handles.Count switch
        {
            0 => null,
            1 => handles[0],
            _ => throw new InvalidOperationException($"Multiple CA state objects labelled '{label}' found on the token."),
        };
    }
}

public static class CaStateStores
{
    public const string TokenSelector = "token";

    /// <summary>--state semantics: a file path, or the literal "token" for on-token state.</summary>
    public static bool IsToken(string state) => state == TokenSelector;
}
