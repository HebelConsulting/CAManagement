using CertificateAuthority;

namespace CAConsole.Infrastructure;

/// <summary>
/// Parses a simple "CN=Test CA, O=Org, C=CH" subject string. Components are
/// encoded in the order given; escaping/quoting (full RFC 4514) is not supported.
/// </summary>
public static class SubjectParser
{
    public static DistinguishedName Parse(string subject)
    {
        var builder = DistinguishedName.Builder();

        foreach (var component in subject.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = component.Split('=', 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2)
            {
                throw new FormatException($"Invalid subject component '{component}' (expected key=value).");
            }

            var (key, value) = (parts[0].ToUpperInvariant(), parts[1]);
            _ = key switch
            {
                "CN" => builder.CommonName(value),
                "O" => builder.Organization(value),
                "OU" => builder.OrganizationalUnit(value),
                "C" => builder.Country(value),
                "L" => builder.Locality(value),
                "ST" => builder.StateOrProvince(value),
                "DC" => builder.Add(Oids.DomainComponent, value),
                "E" or "EMAILADDRESS" => builder.Add(Oids.EmailAddress, value),
                "SERIALNUMBER" => builder.Add(Oids.SerialNumberAttribute, value),
                _ => throw new FormatException($"Unsupported subject attribute '{parts[0]}'."),
            };
        }

        return builder.Build();
    }
}
