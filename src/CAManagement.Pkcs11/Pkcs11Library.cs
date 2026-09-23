using System.Runtime.InteropServices;
using Microsoft.Extensions.Options;
using CAManagement.Pkcs11.Configuration;
using CAManagement.Pkcs11.DataStructures;
using CAManagement.Pkcs11.Extensions;
using static CAManagement.Pkcs11.DataStructures.CK_C_INITIALIZE_ARGS_FLAGS;
using static CAManagement.Pkcs11.DataStructures.CK_SESSION_INFO_FLAGS;

namespace CAManagement.Pkcs11;

/// <summary>
/// A loaded PKCS#11 module. Resolves only <c>C_GetFunctionList</c> from the native
/// library and calls every other function through the pointers it returns
/// (SPEC decisions #1, #2). Owns the module handle and the Cryptoki lifetime:
/// disposing calls <c>C_Finalize</c> and unloads the library (SPEC #7).
/// </summary>
public sealed partial class Pkcs11Library : IDisposable
{
    private readonly Pkcs11Options _options;

    private readonly IntPtr _moduleHandle;

    private CK_FUNCTION_LIST _functions;

    private bool _disposed;

    public CK_VERSION CryptokiVersion => _functions.Version;

    public Pkcs11Library(IOptions<Pkcs11Options> options) : this(options.Value)
    {
    }

    public Pkcs11Library(Pkcs11Options options)
    {
        _options = options;
        _moduleHandle = NativeLibrary.Load(options.ModulePath);

        var getFunctionList = Marshal.GetDelegateForFunctionPointer<CkGetFunctionListDelegate>(
            NativeLibrary.GetExport(_moduleHandle, "C_GetFunctionList"));
        CheckRv(getFunctionList(out var functionListPtr), "C_GetFunctionList");
        _functions = Marshal.PtrToStructure<CK_FUNCTION_LIST>(functionListPtr);

        BindFunctions();

        var initializeArgs = new CK_C_INITIALIZE_ARGS
        {
            Flags = options.UseOsLocking ? CKF_OS_LOCKING_OK : 0,
        };
        Initialize(ref initializeArgs);
    }

    /// <summary>Opens a session on the configured slot (SPEC #9).</summary>
    public Pkcs11Session OpenSession(bool readWrite = true) => OpenSession(ResolveSlot(), readWrite);

    /// <summary>Opens a session on an explicit slot (e.g. a freshly initialized token with no label yet).</summary>
    public Pkcs11Session OpenSession(NativeULong slotId, bool readWrite = true)
    {
        var flags = CKF_SERIAL_SESSION | (readWrite ? CKF_RW_SESSION : 0);
        var handle = OpenSession(slotId, (NativeULong)flags);

        return new Pkcs11Session(this, slotId, handle);
    }

    /// <summary>
    /// The first slot whose token is present but not yet initialized, mirroring
    /// <c>softhsm2-util --free</c>. Throws if none is available.
    /// </summary>
    public NativeULong FindFreeSlot()
    {
        foreach (var slot in GetSlotList(tokenPresent: true))
        {
            if (!GetTokenInfo(slot).Flags.HasFlag(CK_TOKEN_INFO_FLAGS.CKF_TOKEN_INITIALIZED))
            {
                return slot;
            }
        }

        throw new InvalidOperationException("No free (uninitialized) token slot is available.");
    }

    private NativeULong ResolveSlot()
    {
        if (_options.SlotId is { } slotId)
        {
            return slotId;
        }

        var slots = GetSlotList(tokenPresent: true);

        if (_options.TokenLabel is { } label)
        {
            // Collected, not first-match-wins. A label is a NAME, and two tokens wearing one name is an
            // ambiguity the caller cannot see: picking either would open a session on keys that merely
            // look right, and for an envelope-encryption consumer that means wrapping against one token
            // and failing to unwrap against another — silently unreadable data, with every call returning
            // success. Observed in the wild (SimplArchiveEncryption, 2026-09-23): a provisioning script
            // whose "does the token exist?" test mis-fired created a second token with the same label on
            // every restart, and the service happily minted fresh keys against it.
            var matches = slots.Where(slot => GetTokenInfo(slot).Label.AsPkcs11String() == label).ToList();

            return matches.Count switch
            {
                1 => matches[0],
                0 => throw new InvalidOperationException($"No slot found with a token labelled '{label}'."),
                _ => throw new InvalidOperationException(
                    $"{matches.Count} tokens are labelled '{label}' (slots {string.Join(", ", matches)}). "
                    + "Refusing to guess which one holds your keys — pass an explicit SlotId, or remove the "
                    + "duplicates."),
            };
        }

        return slots.Length > 0
            ? slots[0]
            : throw new InvalidOperationException("No slot with a present token was found.");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Best-effort teardown; never throw from Dispose.
        _cFinalize?.Invoke(IntPtr.Zero);

        if (_moduleHandle != IntPtr.Zero)
        {
            NativeLibrary.Free(_moduleHandle);
        }
    }
}
