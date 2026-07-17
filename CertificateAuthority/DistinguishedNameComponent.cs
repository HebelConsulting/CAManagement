using System.Formats.Asn1;

namespace CertificateAuthority;

/// <summary>
/// One RDN component. <paramref name="StringType"/> overrides the default
/// per-attribute encoding; it is set when parsing annotated strings and when
/// decoding DER whose encoding differs from our defaults (byte fidelity on
/// re-encode, e.g. an openssl-issued CA with a PrintableString CN).
/// </summary>
public sealed record DistinguishedNameComponent(string Oid, string Value, UniversalTagNumber? StringType = null);
