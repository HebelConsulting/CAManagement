namespace CertificateAuthority;

/// <summary>RFC 5280 KeyUsage named bits (bit n corresponds to value 1 &lt;&lt; n).</summary>
[Flags]
public enum KeyUsages
{
    None = 0,
    DigitalSignature = 1 << 0,
    NonRepudiation = 1 << 1,
    KeyEncipherment = 1 << 2,
    DataEncipherment = 1 << 3,
    KeyAgreement = 1 << 4,
    KeyCertSign = 1 << 5,
    CrlSign = 1 << 6,
    EncipherOnly = 1 << 7,
    DecipherOnly = 1 << 8,
}
