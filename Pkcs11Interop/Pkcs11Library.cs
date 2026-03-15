using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Pkcs11Interop.DataStructures;
using NativeULong = System.UInt64;

namespace Pkcs11Interop;

public partial class Pkcs11Library
{
    private CK_C_INITIALIZE_ARGS CkCInitializeArgs { get; } = new CK_C_INITIALIZE_ARGS();
    
    private string? Module { get; }

    public Pkcs11Library(string module)
    {
        //NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), DllImportResolver);
        
        var getFunctionList = GetFunctionList(out IntPtr getFunctionListPtr);
        var functionList = Marshal.PtrToStructure<CK_FUNCTION_LIST>(getFunctionListPtr);
    }

    private IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if ("softhsm2" == libraryName)
        {
            return NativeLibrary.Load(Module!, assembly, searchPath);
        }

        return IntPtr.Zero;
    }
    
    [LibraryImport("libraryName", EntryPoint = "C_GetFunctionList")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_GetFunctionList(out IntPtr cGetFunctionListPtr);
    
    private CK_RV GetFunctionList(out IntPtr cGetFunctionListPtr) => C_GetFunctionList(out cGetFunctionListPtr);
    
    [LibraryImport("libraryName", EntryPoint = "C_Initialize")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_Initialize(ref CK_C_INITIALIZE_ARGS args);
    private CK_RV Initialize(ref CK_C_INITIALIZE_ARGS args) => C_Initialize(ref args);
    
    [LibraryImport("libraryName", EntryPoint = "C_GetSlotList")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_GetSlotList([MarshalAs(UnmanagedType.Bool)] bool tokenPresent, [In] NativeULong[]? slotList, out NativeULong count);
    
    [LibraryImport("libraryName", EntryPoint = "C_GetSlotInfo")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_GetSlotInfo(NativeULong slot, out CK_SLOT_INFO ckSlotInfo);
    internal CK_RV GetSlotInfo(NativeULong slot, out CK_SLOT_INFO ckSlotInfo) => C_GetSlotInfo(slot, out ckSlotInfo);
    
    [LibraryImport("libraryName", EntryPoint = "C_GetTokenInfo")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_GetTokenInfo(NativeULong slot, out CK_TOKEN_INFO ckTokenInfo);
    internal CK_RV GetTokenInfo(NativeULong slot, out CK_TOKEN_INFO ckTokenInfo) => C_GetTokenInfo(slot, out ckTokenInfo);
    
    [LibraryImport("libraryName", EntryPoint = "C_CloseAllSessions")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_CloseAllSessions(NativeULong slotId);
    internal CK_RV CloseAllSessions(NativeULong slotId) => C_CloseAllSessions(slotId);

    [LibraryImport("libraryName", EntryPoint = "C_Finalize")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_Finalize(IntPtr reserved);
    private CK_RV Finalize(IntPtr reserved) => C_Finalize(reserved);

    [LibraryImport("libraryName", EntryPoint = "C_OpenSession")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_OpenSession(NativeULong slot, CK_SESSION_INFO_FLAGS flags, IntPtr pApplication,
        IntPtr notify, out NativeULong sessionHandle);
    private CK_RV OpenSession(NativeULong slot,  CK_SESSION_INFO_FLAGS flags, IntPtr pApplication,  IntPtr notify, out NativeULong sessionHandle)  => C_OpenSession(slot, flags, pApplication, notify, out sessionHandle);
    
    [LibraryImport("libraryName", EntryPoint = "C_CloseSession")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_CloseSession(NativeULong sessionHandle);
    private CK_RV CloseSession(NativeULong sessionHandle) => C_CloseSession(sessionHandle);
    
    [LibraryImport("libraryName", EntryPoint = "C_GetAttributeValue")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_GetAttributeValue(NativeULong session, NativeULong objHandle, [In, Out] CK_ATTRIBUTE[] attributes, out NativeULong attributeLength);
    private CK_RV GetAttributeValue(NativeULong session, NativeULong objHandle, [In, Out] CK_ATTRIBUTE[] attributes,  out NativeULong attributeLength)  => C_GetAttributeValue(session, objHandle, attributes, out attributeLength);


    [LibraryImport("libraryName", EntryPoint = "C_Login")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_Login(NativeULong session, CKU userType, [In] byte[] pin, NativeULong pinLength);
    private CK_RV Login(NativeULong session, CKU userType, [In] byte[] pin) => C_Login(session, userType, pin, (ulong)pin.Length);
    private CK_RV Login(NativeULong session, CKU userType, string pinString) => Login(session, userType, Encoding.UTF8.GetBytes(pinString));
    
    [LibraryImport("libraryName", EntryPoint = "C_Logout")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_Logout(NativeULong session);
    private CK_RV Logout(NativeULong session) => C_Logout(session);
    
    // Signing
    [LibraryImport("libraryName", EntryPoint = "C_CreateSession")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_SignInit(NativeULong session, ref CK_MECHANISM mechanism, NativeULong objHandle);
    private CK_RV SignInit(NativeULong session, ref CK_MECHANISM mechanism, NativeULong objHandle) => C_SignInit(session, ref mechanism, objHandle);

    [LibraryImport("libraryName", EntryPoint = "C_Sign")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_Sign(NativeULong session, byte[] data, NativeULong dataLength, byte[] signature, out NativeULong signatureLength);
    private CK_RV Sign(NativeULong session, byte[] data, NativeULong dataLength, byte[] signature, out NativeULong signatureLength)  => C_Sign(session, data, dataLength, signature, out signatureLength);
    
    [LibraryImport("libraryName", EntryPoint = "C_SignFinal")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_SignFinal(NativeULong session, byte[] signature, NativeULong signatureLength);
    private CK_RV SignFinal(NativeULong session, byte[] signature, NativeULong signatureLength) => C_SignFinal(session, signature, signatureLength);

    private CK_KEY_TYPE GetKeyType(CK_MECHANISM_TYPE mechanismType) => mechanismType switch
    {
        CK_MECHANISM_TYPE.CKM_RSA_PKCS => CK_KEY_TYPE.CKK_RSA,
        CK_MECHANISM_TYPE.CKM_SHA256_RSA_PKCS => CK_KEY_TYPE.CKK_RSA,
        CK_MECHANISM_TYPE.CKM_ECDSA => CK_KEY_TYPE.CKK_ECDSA,
        CK_MECHANISM_TYPE.CKM_ECDSA_SHA256 => CK_KEY_TYPE.CKK_ECDSA,
        _ => throw new ArgumentOutOfRangeException(nameof(mechanismType)),
    };

    private NativeULong GetUniqueKeyHandle(List<NativeULong> list) => list switch
    {
        _ when (list.Count == 1) => list.FirstOrDefault(),
        _ => throw new ArgumentOutOfRangeException(nameof(list)),
    };
    
    public byte[] Sign(CK_MECHANISM_TYPE mechanismType, byte[] data)
    {
        var privateKeyHandles = FindObjects(CK_OBJECT_CLASS.CKO_PRIVATE_KEY, GetKeyType(mechanismType)).ToList();
        var objectHandlePrivateKey = GetUniqueKeyHandle(privateKeyHandles);
        
        var mechanism = CreateMechanism(mechanismType, null);
        
        var rvSignInit = SignInit(1, ref mechanism, objectHandlePrivateKey); // Set session Id
        var sign = Sign(1, data, (NativeULong)data.Length, null!, out var signatureLength);
        var signature = new byte[signatureLength];
        var sign2 = Sign(1, data, (NativeULong)data.Length, signature, out signatureLength);

        return signature;
    }
    
    // Verifying
    [LibraryImport("libraryName", EntryPoint = "C_VerifyInit")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_VerifyInit(NativeULong session, ref CK_MECHANISM mechanism,  NativeULong objHandle);
    private CK_RV VerifyInit(NativeULong session, ref CK_MECHANISM mechanism,  NativeULong objHandle)  => C_VerifyInit(session, ref mechanism, objHandle);
    
    [LibraryImport("libraryName", EntryPoint = "C_Verify")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_Verify(NativeULong session, byte[] data, NativeULong dataLength, byte[] signature, NativeULong signatureLength);
    private CK_RV Verify(NativeULong session, byte[] data, NativeULong dataLength, byte[] signature,  NativeULong signatureLength) => C_Verify(session, data, dataLength, signature, signatureLength);

    public bool Verify(CK_MECHANISM_TYPE mechanismType, byte[] data, byte[] signature)
    {
        var verifyingMechanism = CreateMechanism(mechanismType, null!);
        
        var publicKeyHandles = FindObjects(CK_OBJECT_CLASS.CKO_PUBLIC_KEY, GetKeyType(mechanismType)).ToList();
        var objectHandlePublicKey = GetUniqueKeyHandle(publicKeyHandles);

        var rvVerifyInit = VerifyInit(1, ref verifyingMechanism, objectHandlePublicKey);
        var rvVerify = Verify(1, data, Convert.ToUInt64(data.Length), signature, (NativeULong)signature.Length);

        return CK_RV.CKR_OK == rvVerify;
    }
    
    // FindObjects
    public IEnumerable<NativeULong> FindObjects(CK_OBJECT_CLASS objClass, CK_KEY_TYPE keyType)
    {
        var template = new List<CK_ATTRIBUTE>
        {
            CreateAttribute(CK_ATTRIBUTE_TYPE.CKA_CLASS, objClass),
            CreateAttribute(CK_ATTRIBUTE_TYPE.CKA_TOKEN, true),
            CreateAttribute(CK_ATTRIBUTE_TYPE.CKA_KEY_TYPE, keyType),
        }.ToArray();
        
        var rvFindObjectsInit = FindObjectsInit(1, template, (NativeULong)template.Length);
        var objHandleArray = new NativeULong[10];
        var rvFindObjects = FindObjects(1, objHandleArray, (NativeULong)objHandleArray.Length, out var count);
        var rvFindObjectsFinal = FindObjectsFinal(1);
        
        var list = new List<NativeULong>();

        for (var i = 0x0UL; i < count; i++)
        {
            list.Add(objHandleArray[i]);
        }
        
        return list;
    }
    
    // Finding objects in token
    [LibraryImport("libraryName", EntryPoint = "C_FindObjectsInit")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_FindObjectsInit(NativeULong session, CK_ATTRIBUTE[] attributes, NativeULong attributeLength);
    private CK_RV FindObjectsInit(NativeULong session, CK_ATTRIBUTE[] attributes, NativeULong attributeLength) => C_FindObjectsInit(session, attributes, attributeLength);
    
    [LibraryImport("libraryName", EntryPoint = "C_FindObjects")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_FindObjects(NativeULong session, NativeULong[] objHandles, NativeULong maxResultCount, out NativeULong count);
    private CK_RV FindObjects(NativeULong session, NativeULong[] objHandles, NativeULong maxResultCount, out NativeULong count) => C_FindObjects(session, objHandles, maxResultCount, out count);
    
    [LibraryImport("libraryName", EntryPoint = "C_FindObjectsFinal")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial CK_RV C_FindObjectsFinal(NativeULong session);
    private CK_RV FindObjectsFinal(NativeULong session)  => C_FindObjectsFinal(session);

    public CK_ATTRIBUTE CreateAttribute(CK_ATTRIBUTE_TYPE type, bool value) => _CreateAttribute(type, BoolToBytes(value));

    public byte[] BoolToBytes(bool value)
    {
        byte[] bytes = BitConverter.GetBytes(value);

        var unmanagedSize = 1;
        if(bytes.Length != unmanagedSize) { throw new ArgumentOutOfRangeException($"Unmanaged size of bool ({unmanagedSize}) does not match expected size ({bytes.Length})"); }
        
        return bytes;
    }

    public int SizeOf(Type structureType)
    {
        if (structureType == null)  { throw new ArgumentNullException(nameof(structureType)); }
        
        return Marshal.SizeOf(structureType);
    }

    public byte[] UIn64ToBytes(UInt64 value)
    {
        var bytes = BitConverter.GetBytes(value);
        
        var unmanagedSize = SizeOf(typeof(UInt64));
        if (bytes.Length != unmanagedSize)
        {
            throw new Exception($"Unmanaged size of UInt64 ({unmanagedSize}) does not match expected size ({bytes.Length})");
        }
        
        return bytes;
    }

    public CK_ATTRIBUTE CreateAttribute(CK_ATTRIBUTE_TYPE type, CK_OBJECT_CLASS value) => _CreateAttribute(type, UIn64ToBytes((NativeULong)value));

    public CK_ATTRIBUTE CreateAttribute(CK_ATTRIBUTE_TYPE type, CK_KEY_TYPE value) => _CreateAttribute(type, UIn64ToBytes((NativeULong)value));

    private CK_ATTRIBUTE _CreateAttribute(CK_ATTRIBUTE_TYPE type, byte[] value)
    {
        var attribute = new CK_ATTRIBUTE();
        attribute.Type = type;

        if (value != null)
        {
            attribute.Value = Allocate(value.Length);
            Write(attribute.Value, value);
            attribute.ValueLength = Convert.ToUInt64(value.Length);
        }
        else
        {
            attribute.Value = IntPtr.Zero;
            attribute.ValueLength = 0;
        }
        
        return attribute;
    }

    private IntPtr Allocate(int size)
    {
        if (size <= 0) { throw new ArgumentOutOfRangeException($"Value has to be positive integer ({size})"); }
        
        IntPtr memory = IntPtr.Zero;
        
        memory = Marshal.AllocHGlobal(size);
        Write(memory, new byte[size]);
        
        return memory;
    }
    
    private static object _allocationsLock = new object();
    
    private static Dictionary<IntPtr, int> _allocations = new Dictionary<IntPtr, int>();
    
    private static bool _debugModeEnabled = false;

    private static void Write(IntPtr memory, byte[] content)
    {
        if (IntPtr.Zero == memory) { throw new ArgumentNullException(nameof(memory)); }
        if (null == content) { throw new ArgumentNullException(nameof(content)); }
        
        Marshal.Copy(content, 0, memory, content.Length);
    }

    private CK_MECHANISM CreateMechanism(CK_MECHANISM_TYPE mechanismType, byte[] parameter)
    {
        var mech = new CK_MECHANISM();
        mech.Mechanism = mechanismType;
        
        if (null != parameter && parameter.Length > 0)
        {
            mech.Parameter = Allocate(parameter.Length);
            Write(mech.Parameter, parameter);
            mech.ParameterLength = Convert.ToUInt64(parameter.Length);
        }
        else
        {
            mech.Parameter = IntPtr.Zero;
            mech.ParameterLength = 0;
        }
        
        return mech;
    }
}