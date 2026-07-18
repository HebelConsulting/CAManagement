# CAManagement.Pkcs11.Signing

Bridges CAManagement.X509 and CAManagement.Pkcs11: `Pkcs11CertificateSigner`
implements `ICertificateSigner` with token-resident keys (including the ECDSA
raw r||s → DER conversion) and `Pkcs11PublicKeyReader` builds
SubjectPublicKeyInfo from token public keys.

Part of [CAManagement](https://github.com/HebelConsulting/CAManagement).
