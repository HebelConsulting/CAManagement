using System.Runtime.InteropServices;
using Pkcs11Interop.DataStructures;

namespace Pkcs11Interop;

// Native surface: delegates bound from CK_FUNCTION_LIST pointers, plus the
// CheckRv-guarded wrappers used by Pkcs11Library / Pkcs11Session (SPEC #1, #6).
public sealed partial class Pkcs11Library
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGetFunctionListDelegate(out IntPtr functionList);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkInitializeDelegate(ref CK_C_INITIALIZE_ARGS args);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkFinalizeDelegate(IntPtr reserved);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGetSlotListDelegate([MarshalAs(UnmanagedType.U1)] bool tokenPresent, [In, Out] NativeULong[]? slotList, ref NativeULong count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGetSlotInfoDelegate(NativeULong slotId, out CK_SLOT_INFO info);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGetTokenInfoDelegate(NativeULong slotId, out CK_TOKEN_INFO info);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkOpenSessionDelegate(NativeULong slotId, NativeULong flags, IntPtr application, IntPtr notify, out NativeULong session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkSessionHandleDelegate(NativeULong session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkSlotIdDelegate(NativeULong slotId);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkLoginDelegate(NativeULong session, NativeULong userType, [In] byte[]? pin, NativeULong pinLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGenerateKeyPairDelegate(
        NativeULong session, ref CK_MECHANISM mechanism,
        [In] CK_ATTRIBUTE[] publicTemplate, NativeULong publicCount,
        [In] CK_ATTRIBUTE[] privateTemplate, NativeULong privateCount,
        out NativeULong publicKey, out NativeULong privateKey);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGetAttributeValueDelegate(NativeULong session, NativeULong objectHandle, [In, Out] CK_ATTRIBUTE[] template, NativeULong count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkFindObjectsInitDelegate(NativeULong session, [In] CK_ATTRIBUTE[] template, NativeULong count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkFindObjectsDelegate(NativeULong session, [Out] NativeULong[] objects, NativeULong maxCount, out NativeULong count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkSignVerifyInitDelegate(NativeULong session, ref CK_MECHANISM mechanism, NativeULong key);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkSignDelegate(NativeULong session, [In] byte[] data, NativeULong dataLength, [Out] byte[]? signature, ref NativeULong signatureLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkVerifyDelegate(NativeULong session, [In] byte[] data, NativeULong dataLength, [In] byte[] signature, NativeULong signatureLength);

    private CkInitializeDelegate _cInitialize = null!;
    private CkFinalizeDelegate _cFinalize = null!;
    private CkGetSlotListDelegate _cGetSlotList = null!;
    private CkGetSlotInfoDelegate _cGetSlotInfo = null!;
    private CkGetTokenInfoDelegate _cGetTokenInfo = null!;
    private CkOpenSessionDelegate _cOpenSession = null!;
    private CkSessionHandleDelegate _cCloseSession = null!;
    private CkSlotIdDelegate _cCloseAllSessions = null!;
    private CkLoginDelegate _cLogin = null!;
    private CkSessionHandleDelegate _cLogout = null!;
    private CkGenerateKeyPairDelegate _cGenerateKeyPair = null!;
    private CkGetAttributeValueDelegate _cGetAttributeValue = null!;
    private CkFindObjectsInitDelegate _cFindObjectsInit = null!;
    private CkFindObjectsDelegate _cFindObjects = null!;
    private CkSessionHandleDelegate _cFindObjectsFinal = null!;
    private CkSignVerifyInitDelegate _cSignInit = null!;
    private CkSignDelegate _cSign = null!;
    private CkSignVerifyInitDelegate _cVerifyInit = null!;
    private CkVerifyDelegate _cVerify = null!;

    private void BindFunctions()
    {
        _cInitialize = Bind<CkInitializeDelegate>(_functions.C_Initialize, nameof(_functions.C_Initialize));
        _cFinalize = Bind<CkFinalizeDelegate>(_functions.C_Finalize, nameof(_functions.C_Finalize));
        _cGetSlotList = Bind<CkGetSlotListDelegate>(_functions.C_GetSlotList, nameof(_functions.C_GetSlotList));
        _cGetSlotInfo = Bind<CkGetSlotInfoDelegate>(_functions.C_GetSlotInfo, nameof(_functions.C_GetSlotInfo));
        _cGetTokenInfo = Bind<CkGetTokenInfoDelegate>(_functions.C_GetTokenInfo, nameof(_functions.C_GetTokenInfo));
        _cOpenSession = Bind<CkOpenSessionDelegate>(_functions.C_OpenSession, nameof(_functions.C_OpenSession));
        _cCloseSession = Bind<CkSessionHandleDelegate>(_functions.C_CloseSession, nameof(_functions.C_CloseSession));
        _cCloseAllSessions = Bind<CkSlotIdDelegate>(_functions.C_CloseAllSessions, nameof(_functions.C_CloseAllSessions));
        _cLogin = Bind<CkLoginDelegate>(_functions.C_Login, nameof(_functions.C_Login));
        _cLogout = Bind<CkSessionHandleDelegate>(_functions.C_Logout, nameof(_functions.C_Logout));
        _cGenerateKeyPair = Bind<CkGenerateKeyPairDelegate>(_functions.C_GenerateKeyPair, nameof(_functions.C_GenerateKeyPair));
        _cGetAttributeValue = Bind<CkGetAttributeValueDelegate>(_functions.C_GetAttributeValue, nameof(_functions.C_GetAttributeValue));
        _cFindObjectsInit = Bind<CkFindObjectsInitDelegate>(_functions.C_FindObjectsInit, nameof(_functions.C_FindObjectsInit));
        _cFindObjects = Bind<CkFindObjectsDelegate>(_functions.C_FindObjects, nameof(_functions.C_FindObjects));
        _cFindObjectsFinal = Bind<CkSessionHandleDelegate>(_functions.C_FindObjectsFinal, nameof(_functions.C_FindObjectsFinal));
        _cSignInit = Bind<CkSignVerifyInitDelegate>(_functions.C_SignInit, nameof(_functions.C_SignInit));
        _cSign = Bind<CkSignDelegate>(_functions.C_Sign, nameof(_functions.C_Sign));
        _cVerifyInit = Bind<CkSignVerifyInitDelegate>(_functions.C_VerifyInit, nameof(_functions.C_VerifyInit));
        _cVerify = Bind<CkVerifyDelegate>(_functions.C_Verify, nameof(_functions.C_Verify));
    }

    private static T Bind<T>(IntPtr pointer, string name) where T : Delegate => pointer == IntPtr.Zero
        ? throw new InvalidOperationException($"The PKCS#11 module does not provide '{name}'.")
        : Marshal.GetDelegateForFunctionPointer<T>(pointer);

    internal static void CheckRv(CK_RV returnValue, string operation, params CK_RV[] allowed)
    {
        if (returnValue == CK_RV.CKR_OK || Array.IndexOf(allowed, returnValue) >= 0)
        {
            return;
        }

        throw new Pkcs11Exception(returnValue, operation);
    }

    private void Initialize(ref CK_C_INITIALIZE_ARGS args) => CheckRv(_cInitialize(ref args), "C_Initialize");

    private NativeULong[] GetSlotList(bool tokenPresent)
    {
        NativeULong count = 0;
        CheckRv(_cGetSlotList(tokenPresent, null, ref count), "C_GetSlotList");

        var slotList = new NativeULong[count];
        CheckRv(_cGetSlotList(tokenPresent, slotList, ref count), "C_GetSlotList");

        return slotList[..(int)count];
    }

    private CK_TOKEN_INFO GetTokenInfo(NativeULong slotId)
    {
        CheckRv(_cGetTokenInfo(slotId, out var info), "C_GetTokenInfo");
        return info;
    }

    internal CK_SLOT_INFO GetSlotInfo(NativeULong slotId)
    {
        CheckRv(_cGetSlotInfo(slotId, out var info), "C_GetSlotInfo");
        return info;
    }

    internal CK_TOKEN_INFO TokenInfo(NativeULong slotId) => GetTokenInfo(slotId);

    private NativeULong OpenSession(NativeULong slotId, NativeULong flags)
    {
        CheckRv(_cOpenSession(slotId, flags, IntPtr.Zero, IntPtr.Zero, out var session), "C_OpenSession");
        return session;
    }

    internal void CloseSession(NativeULong session) => CheckRv(_cCloseSession(session), "C_CloseSession");

    internal void CloseAllSessions(NativeULong slotId) => CheckRv(_cCloseAllSessions(slotId), "C_CloseAllSessions");

    internal void Login(NativeULong session, CKU userType, byte[]? pin) =>
        CheckRv(_cLogin(session, (NativeULong)userType, pin, (NativeULong)(pin?.Length ?? 0)), "C_Login");

    internal void Logout(NativeULong session) => CheckRv(_cLogout(session), "C_Logout");

    internal (NativeULong publicKey, NativeULong privateKey) GenerateKeyPair(
        NativeULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicTemplate, CK_ATTRIBUTE[] privateTemplate)
    {
        CheckRv(
            _cGenerateKeyPair(session, ref mechanism, publicTemplate, (NativeULong)publicTemplate.Length,
                privateTemplate, (NativeULong)privateTemplate.Length, out var publicKey, out var privateKey),
            "C_GenerateKeyPair");

        return (publicKey, privateKey);
    }

    internal byte[] GetAttributeValue(NativeULong session, NativeULong objectHandle, CK_ATTRIBUTE_TYPE type)
    {
        // Two-phase read (PKCS#11 2.40 §5.7.5): probe with a null value pointer to
        // learn the size, then allocate and fetch. Sensitive/invalid attributes
        // return CKR_ATTRIBUTE_SENSITIVE / CKR_ATTRIBUTE_TYPE_INVALID and throw.
        var template = new[] { new CK_ATTRIBUTE { Type = type } };
        CheckRv(_cGetAttributeValue(session, objectHandle, template, 1), "C_GetAttributeValue");

        using var scope = new NativeAllocationScope();
        var length = (int)template[0].ValueLength;
        template[0].Value = scope.Allocate(new byte[length]);
        CheckRv(_cGetAttributeValue(session, objectHandle, template, 1), "C_GetAttributeValue");

        var value = new byte[(int)template[0].ValueLength];
        Marshal.Copy(template[0].Value, value, 0, value.Length);

        return value;
    }

    internal NativeULong[] FindObjects(NativeULong session, CK_ATTRIBUTE[] template, int maxCount)
    {
        CheckRv(_cFindObjectsInit(session, template, (NativeULong)template.Length), "C_FindObjectsInit");

        var buffer = new NativeULong[maxCount];
        CheckRv(_cFindObjects(session, buffer, (NativeULong)maxCount, out var count), "C_FindObjects");
        CheckRv(_cFindObjectsFinal(session), "C_FindObjectsFinal");

        return buffer[..(int)count];
    }

    internal void SignInit(NativeULong session, CK_MECHANISM mechanism, NativeULong key) =>
        CheckRv(_cSignInit(session, ref mechanism, key), "C_SignInit");

    internal byte[] Sign(NativeULong session, byte[] data)
    {
        // Length-probe: first call with a null buffer reports the size (SPEC #6 carve-out).
        NativeULong length = 0;
        CheckRv(_cSign(session, data, (NativeULong)data.Length, null, ref length), "C_Sign", CK_RV.CKR_BUFFER_TOO_SMALL);

        var signature = new byte[length];
        CheckRv(_cSign(session, data, (NativeULong)data.Length, signature, ref length), "C_Sign");

        return length == (NativeULong)signature.Length ? signature : signature[..(int)length];
    }

    internal void VerifyInit(NativeULong session, CK_MECHANISM mechanism, NativeULong key) =>
        CheckRv(_cVerifyInit(session, ref mechanism, key), "C_VerifyInit");

    internal bool Verify(NativeULong session, byte[] data, byte[] signature)
    {
        var returnValue = _cVerify(session, data, (NativeULong)data.Length, signature, (NativeULong)signature.Length);

        return returnValue switch
        {
            CK_RV.CKR_OK => true,
            CK_RV.CKR_SIGNATURE_INVALID => false,
            _ => throw new Pkcs11Exception(returnValue, "C_Verify"),
        };
    }
}
