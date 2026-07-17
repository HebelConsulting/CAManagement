namespace CertificateAuthority;

/// <summary>
/// Signs to-be-signed structures on behalf of the CA. Implementations own the key
/// (HSM, software, ...) and MUST return the signature in the DER form expected in
/// an X.509 signatureValue BIT STRING — i.e. ECDSA signatures as
/// <c>SEQUENCE { r INTEGER, s INTEGER }</c>, RSA PKCS#1 v1.5 as the raw block.
/// </summary>
public interface ICertificateSigner
{
    SignatureAlgorithm SignatureAlgorithm { get; }

    byte[] Sign(byte[] data);
}
