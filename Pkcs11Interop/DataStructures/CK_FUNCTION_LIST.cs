using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace Pkcs11Interop.DataStructures;

[StructLayout(LayoutKind.Sequential)]
public struct CK_FUNCTION_LIST
{
    public CK_VERSION Version;

    public IntPtr C_Initialize;

    public IntPtr C_Finalize;

    public IntPtr C_GetInfo;

    public IntPtr C_GetFunctionList;

    public IntPtr C_GetSlotList;

    public IntPtr C_GetSlotInfo;

    public IntPtr C_GetTokenInfo;

    public IntPtr C_GetMechanismList;

    public IntPtr C_GetMechanismInfo;

    public IntPtr C_InitToken;

    public IntPtr C_InitPIN;

    public IntPtr C_SetPIN;

    public IntPtr C_OpenSession;

    public IntPtr C_CloseSession;

    public IntPtr C_CloseAllSessions;

    public IntPtr C_GetSessionInfo;

    public IntPtr C_GetOperationState;

    public IntPtr C_SetOperationState;

    public IntPtr C_Login;

    public IntPtr C_Logout;

    public IntPtr C_CreateObject;

    public IntPtr C_CopyObject;

    public IntPtr C_DestroyObject;

    public IntPtr C_GetObjectSize;

    public IntPtr C_GetAttributeValue;

    public IntPtr C_SetAttributeValue;

    public IntPtr C_FindObjectsInit;

    public IntPtr C_FindObjects;

    public IntPtr C_FindObjectsFinal;

    public IntPtr C_EncryptInit;

    public IntPtr C_Encrypt;

    public IntPtr C_EncryptUpdate;

    public IntPtr C_EncryptFinal;

    public IntPtr C_DecryptInit;

    public IntPtr C_Decrypt;

    public IntPtr C_DecryptUpdate;

    public IntPtr C_DecryptFinal;

    public IntPtr C_DigestInit;

    public IntPtr C_Digest;

    public IntPtr C_DigestUpdate;

    public IntPtr C_DigestKey;

    public IntPtr C_DigestFinal;

    public IntPtr C_SignInit;

    public IntPtr C_Sign;

    public IntPtr C_SignUpdate;

    public IntPtr C_SignFinal;

    public IntPtr C_SignRecoverInit;

    public IntPtr C_SignRecover;

    public IntPtr C_VerifyInit;

    public IntPtr C_Verify;

    public IntPtr C_VerifyUpdate;

    public IntPtr C_VerifyFinal;

    public IntPtr C_VerifyRecoverInit;

    public IntPtr C_VerifyRecover;

    public IntPtr C_DigestEncryptUpdate;

    public IntPtr C_DecryptVerifyUpdate;

    public IntPtr C_GenerateKey;

    public IntPtr C_GenerateKeyPair;

    public IntPtr C_WrapKey;

    public IntPtr C_UnwrapKey;

    public IntPtr C_DeriveKey;

    public IntPtr C_SeedRandom;

    public IntPtr C_GenerateRandom;

    public IntPtr C_GetFunctionStatus;

    public IntPtr C_CancelFunction;

    public IntPtr C_WaitForSlotEvent;
}