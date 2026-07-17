using System.Formats.Asn1;
using CertificateAuthority;
using Pkcs11Interop;
using Pkcs11Interop.DataStructures;

namespace Pkcs11Signing;

/// <summary>
/// Builds a <see cref="SubjectPublicKeyInfo"/> from a PKCS#11 public key object.
/// Unwrapping <c>CKA_EC_POINT</c> (a DER OCTET STRING around the raw point) and
/// decoding <c>CKA_EC_PARAMS</c> (a DER OID) are PKCS#11 conventions, so they
/// belong to this adapter rather than the DER library.
/// </summary>
public static class Pkcs11PublicKeyReader
{
    public static SubjectPublicKeyInfo Read(Pkcs11Session session, NativeULong publicKeyHandle) =>
        session.GetKeyType(publicKeyHandle) switch
        {
            CK_KEY_TYPE.CKK_RSA => ReadRsa(session, publicKeyHandle),
            CK_KEY_TYPE.CKK_ECDSA => ReadEc(session, publicKeyHandle),
            var keyType => throw new NotSupportedException($"Unsupported public key type {keyType}."),
        };

    private static SubjectPublicKeyInfo ReadRsa(Pkcs11Session session, NativeULong publicKeyHandle) =>
        SubjectPublicKeyInfo.FromRsa(
            session.GetAttributeValue(publicKeyHandle, CK_ATTRIBUTE_TYPE.CKA_MODULUS),
            session.GetAttributeValue(publicKeyHandle, CK_ATTRIBUTE_TYPE.CKA_PUBLIC_EXPONENT));

    private static SubjectPublicKeyInfo ReadEc(Pkcs11Session session, NativeULong publicKeyHandle)
    {
        var curveOid = new AsnReader(
                session.GetAttributeValue(publicKeyHandle, CK_ATTRIBUTE_TYPE.CKA_EC_PARAMS), AsnEncodingRules.DER)
            .ReadObjectIdentifier();

        var point = new AsnReader(
                session.GetAttributeValue(publicKeyHandle, CK_ATTRIBUTE_TYPE.CKA_EC_POINT), AsnEncodingRules.DER)
            .ReadOctetString();

        return SubjectPublicKeyInfo.FromEc(curveOid, point);
    }
}
