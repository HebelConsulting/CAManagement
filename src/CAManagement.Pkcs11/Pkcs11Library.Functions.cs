using System.Runtime.InteropServices;
using System.Text;
using CAManagement.Pkcs11.DataStructures;

namespace CAManagement.Pkcs11;

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
    private delegate CK_RV CkGetInfoDelegate(out CK_INFO info);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGetSessionInfoDelegate(NativeULong session, out CK_SESSION_INFO info);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGetMechanismInfoDelegate(NativeULong slotId, CK_MECHANISM_TYPE mechanismType, out CK_MECHANISM_INFO info);

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
    private delegate CK_RV CkCreateObjectDelegate(NativeULong session, [In] CK_ATTRIBUTE[] template, NativeULong count, out NativeULong objectHandle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkDestroyObjectDelegate(NativeULong session, NativeULong objectHandle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGenerateKeyPairDelegate(
        NativeULong session, ref CK_MECHANISM mechanism,
        [In] CK_ATTRIBUTE[] publicTemplate, NativeULong publicCount,
        [In] CK_ATTRIBUTE[] privateTemplate, NativeULong privateCount,
        out NativeULong publicKey, out NativeULong privateKey);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGetAttributeValueDelegate(NativeULong session, NativeULong objectHandle, [In, Out] CK_ATTRIBUTE[] template, NativeULong count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkSetAttributeValueDelegate(NativeULong session, NativeULong objectHandle, [In] CK_ATTRIBUTE[] template, NativeULong count);

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

    // Shared by C_SignUpdate, C_VerifyUpdate and C_InitPIN — all (session, bytes, len).
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkDataPartDelegate(NativeULong session, [In] byte[] data, NativeULong length);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkSignFinalDelegate(NativeULong session, [Out] byte[]? signature, ref NativeULong signatureLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkVerifyFinalDelegate(NativeULong session, [In] byte[] signature, NativeULong signatureLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkGetMechanismListDelegate(NativeULong slotId, [In, Out] CK_MECHANISM_TYPE[]? list, ref NativeULong count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkInitTokenDelegate(NativeULong slotId, [In] byte[] soPin, NativeULong soPinLength, [In] byte[] label);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate CK_RV CkSetPinDelegate(NativeULong session, [In] byte[] oldPin, NativeULong oldPinLength, [In] byte[] newPin, NativeULong newPinLength);

    private CkInitializeDelegate _cInitialize = null!;
    private CkFinalizeDelegate _cFinalize = null!;
    private CkGetInfoDelegate _cGetInfo = null!;
    private CkGetSessionInfoDelegate _cGetSessionInfo = null!;
    private CkGetMechanismInfoDelegate _cGetMechanismInfo = null!;
    private CkGetSlotListDelegate _cGetSlotList = null!;
    private CkGetSlotInfoDelegate _cGetSlotInfo = null!;
    private CkGetTokenInfoDelegate _cGetTokenInfo = null!;
    private CkOpenSessionDelegate _cOpenSession = null!;
    private CkSessionHandleDelegate _cCloseSession = null!;
    private CkSlotIdDelegate _cCloseAllSessions = null!;
    private CkLoginDelegate _cLogin = null!;
    private CkSessionHandleDelegate _cLogout = null!;
    private CkCreateObjectDelegate _cCreateObject = null!;
    private CkDestroyObjectDelegate _cDestroyObject = null!;
    private CkGenerateKeyPairDelegate _cGenerateKeyPair = null!;
    private CkGetAttributeValueDelegate _cGetAttributeValue = null!;
    private CkSetAttributeValueDelegate _cSetAttributeValue = null!;
    private CkFindObjectsInitDelegate _cFindObjectsInit = null!;
    private CkFindObjectsDelegate _cFindObjects = null!;
    private CkSessionHandleDelegate _cFindObjectsFinal = null!;
    private CkSignVerifyInitDelegate _cSignInit = null!;
    private CkSignDelegate _cSign = null!;
    private CkSignVerifyInitDelegate _cVerifyInit = null!;
    private CkVerifyDelegate _cVerify = null!;
    private CkDataPartDelegate _cSignUpdate = null!;
    private CkSignFinalDelegate _cSignFinal = null!;
    private CkDataPartDelegate _cVerifyUpdate = null!;
    private CkVerifyFinalDelegate _cVerifyFinal = null!;
    private CkGetMechanismListDelegate _cGetMechanismList = null!;
    private CkInitTokenDelegate _cInitToken = null!;
    private CkDataPartDelegate _cInitPin = null!;
    private CkSetPinDelegate _cSetPin = null!;

    private void BindFunctions()
    {
        _cInitialize = Bind<CkInitializeDelegate>(_functions.C_Initialize, nameof(_functions.C_Initialize));
        _cFinalize = Bind<CkFinalizeDelegate>(_functions.C_Finalize, nameof(_functions.C_Finalize));
        _cGetInfo = Bind<CkGetInfoDelegate>(_functions.C_GetInfo, nameof(_functions.C_GetInfo));
        _cGetSessionInfo = Bind<CkGetSessionInfoDelegate>(_functions.C_GetSessionInfo, nameof(_functions.C_GetSessionInfo));
        _cGetMechanismInfo = Bind<CkGetMechanismInfoDelegate>(_functions.C_GetMechanismInfo, nameof(_functions.C_GetMechanismInfo));
        _cGetSlotList = Bind<CkGetSlotListDelegate>(_functions.C_GetSlotList, nameof(_functions.C_GetSlotList));
        _cGetSlotInfo = Bind<CkGetSlotInfoDelegate>(_functions.C_GetSlotInfo, nameof(_functions.C_GetSlotInfo));
        _cGetTokenInfo = Bind<CkGetTokenInfoDelegate>(_functions.C_GetTokenInfo, nameof(_functions.C_GetTokenInfo));
        _cOpenSession = Bind<CkOpenSessionDelegate>(_functions.C_OpenSession, nameof(_functions.C_OpenSession));
        _cCloseSession = Bind<CkSessionHandleDelegate>(_functions.C_CloseSession, nameof(_functions.C_CloseSession));
        _cCloseAllSessions = Bind<CkSlotIdDelegate>(_functions.C_CloseAllSessions, nameof(_functions.C_CloseAllSessions));
        _cLogin = Bind<CkLoginDelegate>(_functions.C_Login, nameof(_functions.C_Login));
        _cLogout = Bind<CkSessionHandleDelegate>(_functions.C_Logout, nameof(_functions.C_Logout));
        _cCreateObject = Bind<CkCreateObjectDelegate>(_functions.C_CreateObject, nameof(_functions.C_CreateObject));
        _cDestroyObject = Bind<CkDestroyObjectDelegate>(_functions.C_DestroyObject, nameof(_functions.C_DestroyObject));
        _cGenerateKeyPair = Bind<CkGenerateKeyPairDelegate>(_functions.C_GenerateKeyPair, nameof(_functions.C_GenerateKeyPair));
        _cGetAttributeValue = Bind<CkGetAttributeValueDelegate>(_functions.C_GetAttributeValue, nameof(_functions.C_GetAttributeValue));
        _cSetAttributeValue = Bind<CkSetAttributeValueDelegate>(_functions.C_SetAttributeValue, nameof(_functions.C_SetAttributeValue));
        _cFindObjectsInit = Bind<CkFindObjectsInitDelegate>(_functions.C_FindObjectsInit, nameof(_functions.C_FindObjectsInit));
        _cFindObjects = Bind<CkFindObjectsDelegate>(_functions.C_FindObjects, nameof(_functions.C_FindObjects));
        _cFindObjectsFinal = Bind<CkSessionHandleDelegate>(_functions.C_FindObjectsFinal, nameof(_functions.C_FindObjectsFinal));
        _cSignInit = Bind<CkSignVerifyInitDelegate>(_functions.C_SignInit, nameof(_functions.C_SignInit));
        _cSign = Bind<CkSignDelegate>(_functions.C_Sign, nameof(_functions.C_Sign));
        _cVerifyInit = Bind<CkSignVerifyInitDelegate>(_functions.C_VerifyInit, nameof(_functions.C_VerifyInit));
        _cVerify = Bind<CkVerifyDelegate>(_functions.C_Verify, nameof(_functions.C_Verify));
        _cSignUpdate = Bind<CkDataPartDelegate>(_functions.C_SignUpdate, nameof(_functions.C_SignUpdate));
        _cSignFinal = Bind<CkSignFinalDelegate>(_functions.C_SignFinal, nameof(_functions.C_SignFinal));
        _cVerifyUpdate = Bind<CkDataPartDelegate>(_functions.C_VerifyUpdate, nameof(_functions.C_VerifyUpdate));
        _cVerifyFinal = Bind<CkVerifyFinalDelegate>(_functions.C_VerifyFinal, nameof(_functions.C_VerifyFinal));
        _cGetMechanismList = Bind<CkGetMechanismListDelegate>(_functions.C_GetMechanismList, nameof(_functions.C_GetMechanismList));
        _cInitToken = Bind<CkInitTokenDelegate>(_functions.C_InitToken, nameof(_functions.C_InitToken));
        _cInitPin = Bind<CkDataPartDelegate>(_functions.C_InitPIN, nameof(_functions.C_InitPIN));
        _cSetPin = Bind<CkSetPinDelegate>(_functions.C_SetPIN, nameof(_functions.C_SetPIN));
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

    /// <summary>General library information (<c>C_GetInfo</c>).</summary>
    public CK_INFO GetInfo()
    {
        CheckRv(_cGetInfo(out var info), "C_GetInfo");
        return info;
    }

    internal CK_SESSION_INFO GetSessionInfo(NativeULong session)
    {
        CheckRv(_cGetSessionInfo(session, out var info), "C_GetSessionInfo");
        return info;
    }

    /// <summary>Capabilities of a mechanism on a slot (<c>C_GetMechanismInfo</c>).</summary>
    public CK_MECHANISM_INFO GetMechanismInfo(NativeULong slotId, CK_MECHANISM_TYPE mechanismType)
    {
        CheckRv(_cGetMechanismInfo(slotId, mechanismType, out var info), "C_GetMechanismInfo");
        return info;
    }

    /// <summary>Slot ids (<c>C_GetSlotList</c>), optionally only those with a token present.</summary>
    public NativeULong[] GetSlotList(bool tokenPresent = true)
    {
        NativeULong count = 0;
        CheckRv(_cGetSlotList(tokenPresent, null, ref count), "C_GetSlotList");

        var slotList = new NativeULong[count];
        CheckRv(_cGetSlotList(tokenPresent, slotList, ref count), "C_GetSlotList");

        return slotList[..(int)count];
    }

    /// <summary>Token information for a slot (<c>C_GetTokenInfo</c>).</summary>
    public CK_TOKEN_INFO GetTokenInfo(NativeULong slotId)
    {
        CheckRv(_cGetTokenInfo(slotId, out var info), "C_GetTokenInfo");
        return info;
    }

    /// <summary>Slot information (<c>C_GetSlotInfo</c>).</summary>
    public CK_SLOT_INFO GetSlotInfo(NativeULong slotId)
    {
        CheckRv(_cGetSlotInfo(slotId, out var info), "C_GetSlotInfo");
        return info;
    }

    /// <summary>The mechanisms a slot's token supports (<c>C_GetMechanismList</c>).</summary>
    public CK_MECHANISM_TYPE[] GetMechanismList(NativeULong slotId)
    {
        NativeULong count = 0;
        CheckRv(_cGetMechanismList(slotId, null, ref count), "C_GetMechanismList");

        var list = new CK_MECHANISM_TYPE[count];
        CheckRv(_cGetMechanismList(slotId, list, ref count), "C_GetMechanismList");

        return list[..(int)count];
    }

    private NativeULong OpenSession(NativeULong slotId, NativeULong flags)
    {
        CheckRv(_cOpenSession(slotId, flags, IntPtr.Zero, IntPtr.Zero, out var session), "C_OpenSession");
        return session;
    }

    internal void CloseSession(NativeULong session) => CheckRv(_cCloseSession(session), "C_CloseSession");

    /// <summary>Closes every session this application has open on a slot (<c>C_CloseAllSessions</c>).</summary>
    public void CloseAllSessions(NativeULong slotId) => CheckRv(_cCloseAllSessions(slotId), "C_CloseAllSessions");

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

    internal void SetAttributeValue(NativeULong session, NativeULong objectHandle, CK_ATTRIBUTE[] template) =>
        CheckRv(_cSetAttributeValue(session, objectHandle, template, (NativeULong)template.Length), "C_SetAttributeValue");

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

    internal NativeULong CreateObject(NativeULong session, CK_ATTRIBUTE[] template)
    {
        CheckRv(_cCreateObject(session, template, (NativeULong)template.Length, out var objectHandle), "C_CreateObject");
        return objectHandle;
    }

    internal void DestroyObject(NativeULong session, NativeULong objectHandle) =>
        CheckRv(_cDestroyObject(session, objectHandle), "C_DestroyObject");

    internal NativeULong[] FindObjects(NativeULong session, CK_ATTRIBUTE[] template)
    {
        CheckRv(_cFindObjectsInit(session, template, (NativeULong)template.Length), "C_FindObjectsInit");

        // Page until the module returns fewer handles than requested (PKCS#11 §5.7).
        var handles = new List<NativeULong>();
        var buffer = new NativeULong[64];
        NativeULong count;
        do
        {
            CheckRv(_cFindObjects(session, buffer, (NativeULong)buffer.Length, out count), "C_FindObjects");
            handles.AddRange(buffer[..(int)count]);
        } while (count == (NativeULong)buffer.Length);

        CheckRv(_cFindObjectsFinal(session), "C_FindObjectsFinal");

        return handles.ToArray();
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

    // --- multi-part sign / verify --------------------------------------------

    internal void SignUpdate(NativeULong session, byte[] part) =>
        CheckRv(_cSignUpdate(session, part, (NativeULong)part.Length), "C_SignUpdate");

    internal byte[] SignFinal(NativeULong session)
    {
        NativeULong length = 0;
        CheckRv(_cSignFinal(session, null, ref length), "C_SignFinal", CK_RV.CKR_BUFFER_TOO_SMALL);

        var signature = new byte[length];
        CheckRv(_cSignFinal(session, signature, ref length), "C_SignFinal");

        return length == (NativeULong)signature.Length ? signature : signature[..(int)length];
    }

    internal void VerifyUpdate(NativeULong session, byte[] part) =>
        CheckRv(_cVerifyUpdate(session, part, (NativeULong)part.Length), "C_VerifyUpdate");

    internal bool VerifyFinal(NativeULong session, byte[] signature)
    {
        var returnValue = _cVerifyFinal(session, signature, (NativeULong)signature.Length);

        return returnValue switch
        {
            CK_RV.CKR_OK => true,
            CK_RV.CKR_SIGNATURE_INVALID => false,
            _ => throw new Pkcs11Exception(returnValue, "C_VerifyFinal"),
        };
    }

    // --- token / PIN administration ------------------------------------------

    /// <summary>
    /// Initializes a token in a slot with the SO PIN and label (<c>C_InitToken</c>).
    /// The slot must have no session open. The label is space-padded to 32 bytes.
    /// </summary>
    public void InitializeToken(NativeULong slotId, string securityOfficerPin, string label)
    {
        var pin = Encoding.UTF8.GetBytes(securityOfficerPin);
        CheckRv(_cInitToken(slotId, pin, (NativeULong)pin.Length, EncodeLabel(label)), "C_InitToken");
    }

    internal void InitPin(NativeULong session, byte[] pin) =>
        CheckRv(_cInitPin(session, pin, (NativeULong)pin.Length), "C_InitPIN");

    internal void SetPin(NativeULong session, byte[] oldPin, byte[] newPin) =>
        CheckRv(_cSetPin(session, oldPin, (NativeULong)oldPin.Length, newPin, (NativeULong)newPin.Length), "C_SetPIN");

    /// <summary>PKCS#11 token labels are a fixed 32-byte field, space-padded (not null-terminated).</summary>
    private static byte[] EncodeLabel(string label)
    {
        var bytes = Encoding.UTF8.GetBytes(label);
        if (bytes.Length > 32)
        {
            throw new ArgumentException($"Token label must be at most 32 bytes (got {bytes.Length}).", nameof(label));
        }

        var buffer = new byte[32];
        Array.Fill(buffer, (byte)' ');
        bytes.CopyTo(buffer, 0);

        return buffer;
    }
}
