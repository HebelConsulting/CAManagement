using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CAManagement.Pkcs11;
using CAManagement.Pkcs11.DataStructures;

namespace CAManagement.Tests.Integration;

[Collection(SoftHsmCollection.Name)]
public sealed class ObjectManagementTests(SoftHsmFixture fixture)
{
    [Fact]
    public void Imports_finds_reads_and_destroys_an_x509_certificate()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=ca-test-cert", ecdsa, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var label = $"cert-{Guid.NewGuid():N}";
        var handle = session.ImportX509Certificate(
            label, certificate.RawData, certificate.SubjectName.RawData, id: [0x01, 0x02]);

        var found = session.FindObjects(CK_OBJECT_CLASS.CKO_CERTIFICATE, label);
        Assert.Equal([handle], found);

        Assert.Equal(CK_OBJECT_CLASS.CKO_CERTIFICATE, session.GetObjectClass(handle));
        Assert.Equal(certificate.RawData, session.GetAttributeValue(handle, CK_ATTRIBUTE_TYPE.CKA_VALUE));
        Assert.Equal(certificate.SubjectName.RawData, session.GetAttributeValue(handle, CK_ATTRIBUTE_TYPE.CKA_SUBJECT));

        session.DestroyObject(handle);
        Assert.Empty(session.FindObjects(CK_OBJECT_CLASS.CKO_CERTIFICATE, label));
    }

    [Fact]
    public void Data_objects_round_trip_and_finding_pages_past_64_handles()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var label = $"data-{Guid.NewGuid():N}";
        const int objectCount = 70; // crosses the 64-handle FindObjects page size
        var handles = Enumerable.Range(0, objectCount)
            .Select(i => session.CreateDataObject(label, Encoding.UTF8.GetBytes($"payload-{i}")))
            .ToList();

        var found = session.FindObjects(CK_OBJECT_CLASS.CKO_DATA, label);
        Assert.Equal(objectCount, found.Count);
        Assert.Equal(handles.Order(), found.Order());

        Assert.Equal("payload-0"u8.ToArray(), session.GetAttributeValue(handles[0], CK_ATTRIBUTE_TYPE.CKA_VALUE));

        foreach (var handle in handles)
        {
            session.DestroyObject(handle);
        }

        Assert.Empty(session.FindObjects(CK_OBJECT_CLASS.CKO_DATA, label));
    }

    [Fact]
    public void Data_object_labels_update_in_place_but_values_are_read_only()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var label = $"setattr-{Guid.NewGuid():N}";
        var handle = session.CreateDataObject(label, "initial"u8.ToArray());
        try
        {
            // SoftHSM allows relabelling…
            var newLabel = $"relabelled-{Guid.NewGuid():N}";
            session.SetAttributeValue(handle, CK_ATTRIBUTE_TYPE.CKA_LABEL, System.Text.Encoding.UTF8.GetBytes(newLabel));
            Assert.Equal(newLabel, System.Text.Encoding.UTF8.GetString(
                session.GetAttributeValue(handle, CK_ATTRIBUTE_TYPE.CKA_LABEL)));

            // …but refuses in-place CKA_VALUE updates — the reason TokenCaStateStore
            // uses a staged-rename protocol instead.
            var exception = Assert.Throws<Pkcs11Exception>(() =>
                session.SetAttributeValue(handle, CK_ATTRIBUTE_TYPE.CKA_VALUE, "replacement"u8.ToArray()));
            Assert.Equal(CK_RV.CKR_ATTRIBUTE_READ_ONLY, exception.ReturnValue);
        }
        finally
        {
            session.DestroyObject(handle);
        }
    }

    [Fact]
    public void Destroying_an_invalid_handle_throws_pkcs11_exception()
    {
        using var library = new Pkcs11Library(fixture.CreateOptions());
        using var session = library.OpenSession();
        using var _ = session.Login(SoftHsmFixture.UserPin);

        var exception = Assert.Throws<Pkcs11Exception>(() => session.DestroyObject(0xDEAD_BEEF));

        Assert.Equal(CK_RV.CKR_OBJECT_HANDLE_INVALID, exception.ReturnValue);
    }
}
