# CAManagement.X509

X.509/DER authoring on `System.Formats.Asn1`: certificate issuance
(`CertificateBuilder`), PKCS#10 CSR intake with proof-of-possession
verification, CRL building, OCSP request/response handling, chain validation
helpers and a certutil-style ASN.1 analyzer. Signing is abstracted behind
`ICertificateSigner` — bring an HSM (see CAManagement.Pkcs11.Signing) or a
software key.

Part of [CAManagement](https://github.com/HebelConsulting/CAManagement).
