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
    public Pkcs11Session OpenSession(bool readWrite = true)
    {
        var slot = ResolveSlot();
        var flags = CKF_SERIAL_SESSION | (readWrite ? CKF_RW_SESSION : 0);
        var handle = OpenSession(slot, (NativeULong)flags);

        return new Pkcs11Session(this, slot, handle);
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
            foreach (var slot in slots)
            {
                if (GetTokenInfo(slot).Label.AsPkcs11String() == label)
                {
                    return slot;
                }
            }

            throw new InvalidOperationException($"No slot found with a token labelled '{label}'.");
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
