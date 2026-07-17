using CAManagement.X509;

namespace CAManagement.Cli.Infrastructure;

/// <summary>
/// Parses subject strings via <see cref="DistinguishedName.Parse"/>: comma form
/// ("C=CH, O=Org, CN=name") or OpenSSL slash form ("/C=CH/O=Org/CN=name"),
/// optionally with string-type annotations ("CN=[PrintableString]name").
/// Components are encoded in the order given.
/// </summary>
public static class SubjectParser
{
    public static DistinguishedName Parse(string subject) => DistinguishedName.Parse(subject);
}
