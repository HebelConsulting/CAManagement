using System.Text;

namespace CertificateAuthority.Analysis;

public sealed record AnalyzedDocument(DocumentKind Kind, Asn1Node Root);

/// <summary>
/// certutil-style DER analysis: parses any input (PEM or DER) into a generic tree,
/// detects the document kind, and annotates the nodes with field names and
/// explanations. Detection and annotation are best-effort — unknown or partly
/// unexpected structures still yield the raw tree.
/// </summary>
public static class Asn1Analyzer
{
    public static AnalyzedDocument Analyze(byte[] data)
    {
        // PEM files may start with comment text (e.g. CA bundles), so search
        // anywhere rather than only at the start.
        if (data.AsSpan().IndexOf("-----BEGIN"u8) >= 0)
        {
            return Analyze(Encoding.UTF8.GetString(data));
        }

        return AnalyzeDer(data, pemLabel: null);
    }

    public static AnalyzedDocument Analyze(string pemText) =>
        Pem.TryDecodeFirst(pemText) is { } pem
            ? AnalyzeDer(pem.Der, pem.Label)
            : throw new FormatException("No PEM block found in the input.");

    public static AnalyzedDocument AnalyzeDer(byte[] der, string? pemLabel)
    {
        var roots = Asn1TreeParser.Parse(der);
        if (roots.Count != 1)
        {
            throw new FormatException($"Expected exactly one top-level DER element, found {roots.Count}.");
        }

        var root = roots[0];
        var kind = KindFromPemLabel(pemLabel) ?? DetectKind(root);

        switch (kind)
        {
            case DocumentKind.Certificate: AnnotateCertificate(root); break;
            case DocumentKind.CertificationRequest: AnnotateCertificationRequest(root); break;
            case DocumentKind.CertificateList: AnnotateCertificateList(root); break;
            case DocumentKind.SubjectPublicKeyInfo: AnnotateSubjectPublicKeyInfo(root); break;
            case DocumentKind.Pkcs8PrivateKey: AnnotatePkcs8(root); break;
            case DocumentKind.RsaPrivateKey: AnnotateRsaPrivateKey(root); break;
            case DocumentKind.EcPrivateKey: AnnotateEcPrivateKey(root); break;
            case DocumentKind.Pkcs12: AnnotatePfx(root); break;
            case DocumentKind.Cms: AnnotateContentInfo(root, "ContentInfo", "CMS/PKCS#7 content envelope (RFC 5652)"); break;
        }

        return new AnalyzedDocument(kind, root);
    }

    private static DocumentKind? KindFromPemLabel(string? label) => label switch
    {
        null => null,
        "CERTIFICATE" => DocumentKind.Certificate,
        "CERTIFICATE REQUEST" or "NEW CERTIFICATE REQUEST" => DocumentKind.CertificationRequest,
        "X509 CRL" => DocumentKind.CertificateList,
        "PUBLIC KEY" => DocumentKind.SubjectPublicKeyInfo,
        "PRIVATE KEY" => DocumentKind.Pkcs8PrivateKey,
        "RSA PRIVATE KEY" => DocumentKind.RsaPrivateKey,
        "EC PRIVATE KEY" => DocumentKind.EcPrivateKey,
        "PKCS7" or "CMS" => DocumentKind.Cms,
        "PKCS12" => DocumentKind.Pkcs12,
        _ => DocumentKind.Unknown,
    };

    // --- structural detection -------------------------------------------------

    private static DocumentKind DetectKind(Asn1Node root)
    {
        if (root.TagName != "SEQUENCE")
        {
            return DocumentKind.Unknown;
        }

        var c = root.Children;

        return root switch
        {
            _ when IsCsrShape(c) => DocumentKind.CertificationRequest,
            _ when IsCertificateShape(c) => DocumentKind.Certificate,
            _ when IsCrlShape(c) => DocumentKind.CertificateList,
            _ when IsSpkiShape(c) => DocumentKind.SubjectPublicKeyInfo,
            _ when IsPkcs12Shape(c) => DocumentKind.Pkcs12,
            _ when IsCmsShape(c) => DocumentKind.Cms,
            _ when IsPkcs8Shape(c) => DocumentKind.Pkcs8PrivateKey,
            _ when IsRsaPrivateKeyShape(c) => DocumentKind.RsaPrivateKey,
            _ when IsEcPrivateKeyShape(c) => DocumentKind.EcPrivateKey,
            _ => DocumentKind.Unknown,
        };
    }

    private static bool IsSignedShape(IReadOnlyList<Asn1Node> c) =>
        c.Count == 3 && c[0].TagName == "SEQUENCE" && c[1].TagName == "SEQUENCE" && c[2].TagName == "BIT STRING";

    private static bool IsCsrShape(IReadOnlyList<Asn1Node> c) =>
        IsSignedShape(c)
        && c[0].Children.Count == 4
        && c[0].Children[0] is { TagName: "INTEGER", Value: "0" }
        && c[0].Children[3].TagName == "[0]";

    private static bool IsCertificateShape(IReadOnlyList<Asn1Node> c) =>
        IsSignedShape(c) && c[0].Children.Any(IsValidityShape);

    private static bool IsValidityShape(Asn1Node node) =>
        node.TagName == "SEQUENCE" && node.Children.Count == 2 && node.Children.All(IsTime);

    private static bool IsCrlShape(IReadOnlyList<Asn1Node> c) =>
        IsSignedShape(c) && c[0].Children.Any(IsTime);

    private static bool IsTime(Asn1Node node) => node.TagName is "UTCTime" or "GeneralizedTime";

    private static bool IsSpkiShape(IReadOnlyList<Asn1Node> c) =>
        c.Count == 2
        && c[0].TagName == "SEQUENCE" && c[1].TagName == "BIT STRING"
        && c[0].Children.FirstOrDefault()?.DecodedOid is Oids.RsaEncryption or Oids.EcPublicKey;

    private static bool IsPkcs8Shape(IReadOnlyList<Asn1Node> c) =>
        c.Count >= 3
        && c[0] is { TagName: "INTEGER", Value: "0" }
        && c[1].TagName == "SEQUENCE"
        && c[2].TagName == "OCTET STRING";

    private static bool IsRsaPrivateKeyShape(IReadOnlyList<Asn1Node> c) =>
        c.Count >= 9 && c[0] is { TagName: "INTEGER", Value: "0" } && c.All(n => n.TagName == "INTEGER");

    private static bool IsEcPrivateKeyShape(IReadOnlyList<Asn1Node> c) =>
        c.Count >= 2 && c[0] is { TagName: "INTEGER", Value: "1" } && c[1].TagName == "OCTET STRING";

    private static bool IsPkcs12Shape(IReadOnlyList<Asn1Node> c) =>
        c.Count is 2 or 3
        && c[0] is { TagName: "INTEGER", Value: "3" }
        && c[1].TagName == "SEQUENCE"
        && IsPkcs7ContentType(c[1].Children.FirstOrDefault());

    private static bool IsCmsShape(IReadOnlyList<Asn1Node> c) =>
        c.Count is 1 or 2
        && IsPkcs7ContentType(c[0])
        && (c.Count == 1 || c[1].TagName == "[0]");

    private static bool IsPkcs7ContentType(Asn1Node? node) =>
        node?.DecodedOid?.StartsWith("1.2.840.113549.1.7.", StringComparison.Ordinal) == true;

    // --- annotators -----------------------------------------------------------

    private static void Label(Asn1Node node, string name, string explanation)
    {
        node.Name = name;
        node.Explanation = explanation;
    }

    private static void AnnotateAlgorithm(Asn1Node node, string name, string explanation)
    {
        Label(node, name, explanation);

        if (node.Children.Count > 0)
        {
            Label(node.Children[0], "algorithm", "Algorithm OID");
        }
        if (node.Children.Count > 1)
        {
            Label(node.Children[1], "parameters", "Algorithm parameters (NULL for RSA, named curve for EC)");
        }
    }

    private static void AnnotateName(Asn1Node node, string name, string explanation)
    {
        Label(node, name, explanation);

        foreach (var rdn in node.Children)
        {
            var attribute = rdn.Children.FirstOrDefault();
            var typeOid = attribute?.Children.FirstOrDefault()?.DecodedOid;

            if (typeOid is not null && OidNames.For(typeOid) is { } friendly)
            {
                Label(rdn, friendly, "Relative distinguished name");
            }
        }
    }

    private static void AnnotateExtensions(Asn1Node extensionsSequence)
    {
        foreach (var extension in extensionsSequence.Children)
        {
            var oid = extension.Children.FirstOrDefault()?.DecodedOid;
            Label(extension, oid is not null ? OidNames.For(oid) ?? oid : "extension", "Extension");

            var index = 0;
            Label(extension.Children[index++], "extnID", "Extension type OID");
            if (extension.Children.Count == 3)
            {
                Label(extension.Children[index++], "critical", "Reject the certificate if this extension is not understood");
            }
            if (index < extension.Children.Count)
            {
                Label(extension.Children[index], "extnValue", "DER-encoded extension payload");
            }
        }
    }

    private static void AnnotateSpkiNode(Asn1Node node)
    {
        Label(node, "subjectPublicKeyInfo", "The subject's public key");

        if (node.Children.Count == 2)
        {
            AnnotateAlgorithm(node.Children[0], "algorithm", "Public key algorithm");
            Label(node.Children[1], "subjectPublicKey", "The public key material (BIT STRING)");
        }
    }

    private static void AnnotateCertificate(Asn1Node root)
    {
        Label(root, "Certificate", "X.509 v3 certificate (RFC 5280)");
        if (!IsSignedShape(root.Children))
        {
            return;
        }

        AnnotateAlgorithm(root.Children[1], "signatureAlgorithm", "Algorithm the CA used to sign (must match tbsCertificate.signature)");
        Label(root.Children[2], "signatureValue", "CA's signature over the DER-encoded tbsCertificate");

        var tbs = root.Children[0];
        Label(tbs, "tbsCertificate", "The to-be-signed portion — everything the signature covers");
        var c = tbs.Children;
        var i = 0;

        if (i < c.Count && c[i].TagName == "[0]")
        {
            Label(c[i], "version", "Certificate format version");
            if (c[i].Children.FirstOrDefault() is { } versionInt)
            {
                Label(versionInt, "version", versionInt.Value switch
                {
                    "0" => "v1", "1" => "v2", "2" => "v3", _ => "unknown version",
                });
            }
            i++;
        }

        if (i < c.Count) Label(c[i++], "serialNumber", "Unique serial assigned by the CA");
        if (i < c.Count) AnnotateAlgorithm(c[i++], "signature", "Signature algorithm (repeated inside the signed data)");
        if (i < c.Count) AnnotateName(c[i++], "issuer", "Distinguished name of the issuing CA");

        if (i < c.Count && IsValidityShape(c[i]))
        {
            Label(c[i], "validity", "Validity period");
            Label(c[i].Children[0], "notBefore", "Not valid before");
            Label(c[i].Children[1], "notAfter", "Not valid after");
            i++;
        }

        if (i < c.Count) AnnotateName(c[i++], "subject", "Distinguished name of the certificate holder");
        if (i < c.Count) AnnotateSpkiNode(c[i++]);

        for (; i < c.Count; i++)
        {
            switch (c[i].TagName)
            {
                case "[1]": Label(c[i], "issuerUniqueID", "Deprecated issuer identifier"); break;
                case "[2]": Label(c[i], "subjectUniqueID", "Deprecated subject identifier"); break;
                case "[3]":
                    Label(c[i], "extensions", "v3 extensions");
                    if (c[i].Children.FirstOrDefault() is { } extensionList)
                    {
                        AnnotateExtensions(extensionList);
                    }
                    break;
            }
        }
    }

    private static void AnnotateCertificationRequest(Asn1Node root)
    {
        Label(root, "CertificationRequest", "PKCS#10 certificate signing request (RFC 2986)");
        if (!IsSignedShape(root.Children))
        {
            return;
        }

        AnnotateAlgorithm(root.Children[1], "signatureAlgorithm", "Algorithm the requester used to self-sign");
        Label(root.Children[2], "signature", "Requester's proof-of-possession signature over certificationRequestInfo");

        var info = root.Children[0];
        Label(info, "certificationRequestInfo", "The signed request content");
        var c = info.Children;

        if (c.Count > 0) Label(c[0], "version", "PKCS#10 version (0)");
        if (c.Count > 1) AnnotateName(c[1], "subject", "Requested subject distinguished name");
        if (c.Count > 2) AnnotateSpkiNode(c[2]);

        if (c.Count > 3 && c[3].TagName == "[0]")
        {
            Label(c[3], "attributes", "PKCS#9 attributes (e.g. requested extensions)");

            foreach (var attribute in c[3].Children)
            {
                var oid = attribute.Children.FirstOrDefault()?.DecodedOid;
                Label(attribute, oid is not null ? OidNames.For(oid) ?? oid : "attribute", "Request attribute");

                if (oid == Oids.ExtensionRequest
                    && attribute.Children.ElementAtOrDefault(1)?.Children.FirstOrDefault() is { } requested)
                {
                    AnnotateExtensions(requested);
                }
            }
        }
    }

    private static void AnnotateCertificateList(Asn1Node root)
    {
        Label(root, "CertificateList", "X.509 v2 certificate revocation list (RFC 5280)");
        if (!IsSignedShape(root.Children))
        {
            return;
        }

        AnnotateAlgorithm(root.Children[1], "signatureAlgorithm", "Algorithm the CA used to sign");
        Label(root.Children[2], "signatureValue", "CA's signature over the DER-encoded tbsCertList");

        var tbs = root.Children[0];
        Label(tbs, "tbsCertList", "The to-be-signed portion of the CRL");
        var c = tbs.Children;
        var i = 0;

        if (i < c.Count && c[i].TagName == "INTEGER")
        {
            Label(c[i++], "version", "CRL format version (1 = v2)");
        }

        if (i < c.Count) AnnotateAlgorithm(c[i++], "signature", "Signature algorithm (repeated inside the signed data)");
        if (i < c.Count) AnnotateName(c[i++], "issuer", "Distinguished name of the CRL issuer");
        if (i < c.Count && IsTime(c[i])) Label(c[i++], "thisUpdate", "Issue date of this CRL");
        if (i < c.Count && IsTime(c[i])) Label(c[i++], "nextUpdate", "Date by which the next CRL will be issued");

        if (i < c.Count && c[i].TagName == "SEQUENCE")
        {
            Label(c[i], "revokedCertificates", "Revoked certificate entries");

            foreach (var entry in c[i].Children)
            {
                Label(entry, "revokedCertificate", "One revoked certificate");
                if (entry.Children.Count > 0) Label(entry.Children[0], "userCertificate", "Serial number of the revoked certificate");
                if (entry.Children.Count > 1) Label(entry.Children[1], "revocationDate", "When it was revoked");
                if (entry.Children.Count > 2)
                {
                    Label(entry.Children[2], "crlEntryExtensions", "Per-entry extensions (e.g. reason code)");
                    AnnotateExtensions(entry.Children[2]);
                }
            }
            i++;
        }

        if (i < c.Count && c[i].TagName == "[0]")
        {
            Label(c[i], "crlExtensions", "CRL-level extensions");
            if (c[i].Children.FirstOrDefault() is { } extensionList)
            {
                AnnotateExtensions(extensionList);
            }
        }
    }

    private static void AnnotateSubjectPublicKeyInfo(Asn1Node root)
    {
        AnnotateSpkiNode(root);
        Label(root, "SubjectPublicKeyInfo", "Public key with its algorithm (RFC 5280 §4.1.2.7)");
    }

    private static void AnnotatePkcs8(Asn1Node root)
    {
        Label(root, "PrivateKeyInfo", "PKCS#8 private key (RFC 5208) — contains secret key material");
        var c = root.Children;

        if (c.Count > 0) Label(c[0], "version", "PKCS#8 version (0)");
        if (c.Count > 1) AnnotateAlgorithm(c[1], "privateKeyAlgorithm", "Algorithm of the wrapped key");
        if (c.Count > 2)
        {
            Label(c[2], "privateKey", "The wrapped key structure (OCTET STRING)");

            var algorithmOid = c[1].Children.FirstOrDefault()?.DecodedOid;
            if (c[2].Children.FirstOrDefault() is { } inner)
            {
                switch (algorithmOid)
                {
                    case Oids.RsaEncryption: AnnotateRsaPrivateKey(inner); break;
                    case Oids.EcPublicKey: AnnotateEcPrivateKey(inner); break;
                }
            }
        }
        if (c.Count > 3) Label(c[3], "attributes", "Optional attributes");
    }

    private static void AnnotateRsaPrivateKey(Asn1Node root)
    {
        Label(root, "RSAPrivateKey", "PKCS#1 RSA private key — contains secret key material");

        string[] fields = ["version", "modulus", "publicExponent", "privateExponent", "prime1", "prime2", "exponent1", "exponent2", "coefficient"];
        string[] explanations =
        [
            "PKCS#1 version (0)", "n — the public modulus", "e — the public exponent", "d — SECRET private exponent",
            "p — SECRET prime factor", "q — SECRET prime factor", "d mod (p-1) — SECRET CRT exponent",
            "d mod (q-1) — SECRET CRT exponent", "q^-1 mod p — SECRET CRT coefficient",
        ];

        for (var i = 0; i < root.Children.Count && i < fields.Length; i++)
        {
            Label(root.Children[i], fields[i], explanations[i]);
        }
    }

    private static void AnnotateEcPrivateKey(Asn1Node root)
    {
        Label(root, "ECPrivateKey", "SEC1 EC private key — contains secret key material");
        var c = root.Children;

        if (c.Count > 0) Label(c[0], "version", "SEC1 version (1)");
        if (c.Count > 1) Label(c[1], "privateKey", "SECRET scalar d");

        foreach (var node in c.Skip(2))
        {
            switch (node.TagName)
            {
                case "[0]": Label(node, "parameters", "Named curve"); break;
                case "[1]": Label(node, "publicKey", "The matching public point"); break;
            }
        }
    }

    // --- CMS / PKCS#7 ---------------------------------------------------------

    private static void AnnotateContentInfo(Asn1Node node, string name, string explanation)
    {
        Label(node, name, explanation);
        if (node.Children.Count == 0)
        {
            return;
        }

        var contentType = node.Children[0].DecodedOid;
        Label(node.Children[0], "contentType", "Kind of content that follows");

        if (node.Children.Count < 2)
        {
            return; // degenerate ContentInfo without content
        }

        var content = node.Children[1];
        Label(content, "content", "The typed content");

        switch (contentType)
        {
            case OidNames.Pkcs7SignedData when content.Children.FirstOrDefault() is { } signedData:
                AnnotateSignedData(signedData);
                break;
            case OidNames.Pkcs7Data when content.Children.FirstOrDefault() is { } data:
                Label(data, "data", "Opaque payload (OCTET STRING)");
                break;
            case OidNames.Pkcs7EncryptedData when content.Children.FirstOrDefault() is { } encryptedData:
                AnnotateEncryptedData(encryptedData);
                break;
        }
    }

    private static void AnnotateSignedData(Asn1Node node)
    {
        Label(node, "SignedData", "CMS signed content (a .p7b bundle has certificates but no signers)");
        var c = node.Children;
        var i = 0;

        if (i < c.Count && c[i].TagName == "INTEGER") Label(c[i++], "version", "SignedData syntax version");
        if (i < c.Count && c[i].TagName == "SET")
        {
            Label(c[i], "digestAlgorithms", "Digest algorithms used by the signers");
            foreach (var algorithm in c[i].Children)
            {
                AnnotateAlgorithm(algorithm, "digestAlgorithm", "Digest algorithm");
            }
            i++;
        }
        if (i < c.Count && c[i].TagName == "SEQUENCE")
        {
            AnnotateContentInfo(c[i++], "encapContentInfo", "The content that was signed");
        }

        for (; i < c.Count; i++)
        {
            switch (c[i].TagName)
            {
                case "[0]":
                    Label(c[i], "certificates", "Bundled certificates");
                    foreach (var certificate in c[i].Children)
                    {
                        AnnotateCertificate(certificate);
                    }
                    break;
                case "[1]":
                    Label(c[i], "crls", "Bundled revocation lists");
                    foreach (var crl in c[i].Children)
                    {
                        AnnotateCertificateList(crl);
                    }
                    break;
                case "SET":
                    Label(c[i], "signerInfos", "Per-signer signatures over the content");
                    break;
            }
        }
    }

    private static void AnnotateEncryptedData(Asn1Node node)
    {
        Label(node, "EncryptedData", "Password-encrypted content");
        var c = node.Children;

        if (c.Count > 0) Label(c[0], "version", "EncryptedData syntax version");
        if (c.Count > 1)
        {
            Label(c[1], "encryptedContentInfo", "What is encrypted and how");
            var info = c[1].Children;

            if (info.Count > 0) Label(info[0], "contentType", "Kind of the encrypted content");
            if (info.Count > 1)
            {
                AnnotateAlgorithm(info[1], "contentEncryptionAlgorithm", "Password-based encryption scheme");
                AnnotatePbes2(info[1]);
            }
            if (info.Count > 2) Label(info[2], "encryptedContent", "The ciphertext (needs the password to decode)");
        }
    }

    /// <summary>Drills into PBES2 parameters: PBKDF2 salt/iterations and the cipher/IV.</summary>
    private static void AnnotatePbes2(Asn1Node algorithmIdentifier)
    {
        if (algorithmIdentifier.Children.FirstOrDefault()?.DecodedOid != OidNames.Pbes2
            || algorithmIdentifier.Children.ElementAtOrDefault(1) is not { } parameters)
        {
            return;
        }

        if (parameters.Children.ElementAtOrDefault(0) is { } kdf)
        {
            AnnotateAlgorithm(kdf, "keyDerivationFunc", "How the password becomes a key");

            if (kdf.Children.FirstOrDefault()?.DecodedOid == OidNames.Pbkdf2
                && kdf.Children.ElementAtOrDefault(1) is { } kdfParameters)
            {
                var p = kdfParameters.Children;
                if (p.Count > 0) Label(p[0], "salt", "PBKDF2 salt");
                if (p.Count > 1) Label(p[1], "iterationCount", "PBKDF2 iterations (higher = slower brute force)");
                for (var i = 2; i < p.Count; i++)
                {
                    if (p[i].TagName == "INTEGER") Label(p[i], "keyLength", "Derived key length in bytes");
                    if (p[i].TagName == "SEQUENCE") AnnotateAlgorithm(p[i], "prf", "Pseudo-random function");
                }
            }
        }

        if (parameters.Children.ElementAtOrDefault(1) is { } scheme)
        {
            AnnotateAlgorithm(scheme, "encryptionScheme", "Cipher (parameter is the IV)");
        }
    }

    // --- PKCS#12 --------------------------------------------------------------

    private static void AnnotatePfx(Asn1Node root)
    {
        Label(root, "PFX", "PKCS#12 container (RFC 7292) — bundles keys and certificates");
        var c = root.Children;

        if (c.Count > 0) Label(c[0], "version", "PKCS#12 version (3)");

        if (c.Count > 1)
        {
            AnnotateContentInfo(c[1], "authSafe", "The authenticated safe holding all payloads");

            // authSafe: data -> OCTET STRING encapsulating AuthenticatedSafe (SEQUENCE OF ContentInfo)
            var authenticatedSafe = c[1].Children.ElementAtOrDefault(1)?
                .Children.FirstOrDefault()?
                .Children.FirstOrDefault(n => n.TagName == "SEQUENCE");

            if (authenticatedSafe is not null)
            {
                Label(authenticatedSafe, "AuthenticatedSafe", "One ContentInfo per protection mode");

                foreach (var contentInfo in authenticatedSafe.Children)
                {
                    AnnotateContentInfo(contentInfo, "ContentInfo",
                        "SafeContents — plain (data) or password-encrypted (encryptedData)");

                    if (contentInfo.Children.FirstOrDefault()?.DecodedOid == OidNames.Pkcs7Data
                        && contentInfo.Children.ElementAtOrDefault(1)?.Children.FirstOrDefault()?
                            .Children.FirstOrDefault(n => n.TagName == "SEQUENCE") is { } safeContents)
                    {
                        AnnotateSafeContents(safeContents);
                    }
                }
            }
        }

        if (c.Count > 2)
        {
            AnnotateMacData(c[2]);
        }
    }

    private static void AnnotateSafeContents(Asn1Node node)
    {
        Label(node, "SafeContents", "A list of bags");

        foreach (var bag in node.Children)
        {
            var bagId = bag.Children.FirstOrDefault()?.DecodedOid;
            Label(bag, bagId is not null ? OidNames.For(bagId) ?? bagId : "SafeBag", "One bagged item");

            if (bag.Children.Count > 0) Label(bag.Children[0], "bagId", "Bag type OID");
            if (bag.Children.Count > 1)
            {
                Label(bag.Children[1], "bagValue", "The bag payload");
                AnnotateBagValue(bagId, bag.Children[1]);
            }
            if (bag.Children.Count > 2)
            {
                Label(bag.Children[2], "bagAttributes", "Attributes (friendlyName, localKeyID)");
                foreach (var attribute in bag.Children[2].Children)
                {
                    var attributeOid = attribute.Children.FirstOrDefault()?.DecodedOid;
                    if (attributeOid is not null && OidNames.For(attributeOid) is { } friendly)
                    {
                        Label(attribute, friendly, "Bag attribute");
                    }
                }
            }
        }
    }

    private static void AnnotateBagValue(string? bagId, Asn1Node bagValue)
    {
        switch (bagId)
        {
            case OidNames.CertBag when bagValue.Children.FirstOrDefault() is { } certBag:
                Label(certBag, "CertBag", "A wrapped certificate");
                if (certBag.Children.Count > 0) Label(certBag.Children[0], "certId", "Certificate format");
                if (certBag.Children.ElementAtOrDefault(1)?.Children.FirstOrDefault() is { } octet)
                {
                    Label(octet, "certValue", "DER certificate (OCTET STRING)");
                    if (octet.Children.FirstOrDefault() is { } certificate)
                    {
                        AnnotateCertificate(certificate);
                    }
                }
                break;

            case OidNames.Pkcs8ShroudedKeyBag when bagValue.Children.FirstOrDefault() is { } shrouded:
                Label(shrouded, "EncryptedPrivateKeyInfo", "Password-encrypted PKCS#8 key");
                if (shrouded.Children.Count > 0)
                {
                    AnnotateAlgorithm(shrouded.Children[0], "encryptionAlgorithm", "Password-based encryption scheme");
                    AnnotatePbes2(shrouded.Children[0]);
                }
                if (shrouded.Children.Count > 1)
                {
                    Label(shrouded.Children[1], "encryptedData", "SECRET — the encrypted private key");
                }
                break;
        }
    }

    private static void AnnotateMacData(Asn1Node node)
    {
        Label(node, "macData", "Integrity check over the authSafe (password-derived HMAC)");
        var c = node.Children;

        if (c.Count > 0)
        {
            Label(c[0], "mac", "DigestInfo");
            if (c[0].Children.Count > 0) AnnotateAlgorithm(c[0].Children[0], "digestAlgorithm", "HMAC digest algorithm");
            if (c[0].Children.Count > 1) Label(c[0].Children[1], "digest", "The MAC value");
        }
        if (c.Count > 1) Label(c[1], "macSalt", "Salt for the MAC key derivation");
        if (c.Count > 2) Label(c[2], "iterations", "MAC key derivation iterations");
    }
}
