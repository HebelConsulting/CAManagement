namespace CertificateAuthority;

/// <summary>Builds a <see cref="DistinguishedName"/>; add the most significant component first.</summary>
public sealed class DistinguishedNameBuilder
{
    private readonly List<(string Oid, string Value)> _components = [];

    public DistinguishedNameBuilder Country(string value) => Add(Oids.Country, ValidatedCountry(value));

    public DistinguishedNameBuilder StateOrProvince(string value) => Add(Oids.StateOrProvince, value);

    public DistinguishedNameBuilder Locality(string value) => Add(Oids.Locality, value);

    public DistinguishedNameBuilder Organization(string value) => Add(Oids.Organization, value);

    public DistinguishedNameBuilder OrganizationalUnit(string value) => Add(Oids.OrganizationalUnit, value);

    public DistinguishedNameBuilder CommonName(string value) => Add(Oids.CommonName, value);

    public DistinguishedNameBuilder Add(string oid, string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException($"Attribute {oid} must not be empty.", nameof(value));
        }

        _components.Add((oid, value));
        return this;
    }

    public DistinguishedName Build() => _components.Count > 0
        ? new DistinguishedName(_components.ToArray())
        : throw new InvalidOperationException("A distinguished name needs at least one component.");

    private static string ValidatedCountry(string value) => value.Length == 2
        ? value
        : throw new ArgumentException($"Country must be a two-letter code, got '{value}'.");
}
