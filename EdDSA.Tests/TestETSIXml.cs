using CryptoEx.XML.ETSI;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace CryptoEx.Tests;
public class TestETSIXml
{
    // Some test data for XADES
    public static string message = """
    <Tests xmlns="http://www.adatum.com">
        <Test TestId="0001" TestType="CMD">
        <Name>Convert number to string</Name>
        <CommandLine>Examp1.EXE</CommandLine>
        <Input>1</Input>
        <Output>One</Output>
        </Test>
        <Test TestId="0002" TestType="CMD">
        <Name>Find succeeding characters</Name>
        <CommandLine>Examp2.EXE</CommandLine>
        <Input>abc</Input>
        <Output>def</Output>
        </Test>
        <Test TestId="0003" TestType="GUI">
        <Name>Convert multiple numbers to strings</Name>
        <CommandLine>Examp2.EXE /Verbose</CommandLine>
        <Input>123</Input>
        <Output>One Two Three</Output>
        </Test>
        <Test TestId="0004" TestType="GUI">
        <Name>Find correlated key</Name>
        <CommandLine>Examp3.EXE</CommandLine>
        <Input>a1</Input>
        <Output>b1</Output>
        </Test>
        <Test TestId="0005" TestType="GUI">
        <Name>Count characters</Name>
        <CommandLine>FinalExamp.EXE</CommandLine>
        <Input>This is a test</Input>
        <Output>14</Output>
        </Test>
        <Test TestId="0006" TestType="GUI">
        <Name>Another Test</Name>
        <CommandLine>Examp2.EXE</CommandLine>
        <Input>Test Input</Input>
        <Output>10</Output>
        </Test>
    </Tests>
    """;

    public static string testFile = """
    This is a test
    This is a test again
    """;

    public static string testFileTwo = """
    This is a test
    This is a test again
    This is a test third
    """;

    public static string malformedSign = @"<Tests xmlns=""http://www.adatum.com""><Test TestId=""0001"" TestType=""CMD""><Name>Convert number to string</Name><CommandLine>Examp1.EXE</CommandLine><Input>1</Input><Output>One</Output></Test><Test TestId=""0002"" TestType=""CMD""><Name>Find succeeding characters</Name><CommandLine>Examp2.EXE</CommandLine><Input>abc</Input><Output>def</Output></Test><Test TestId=""0003"" TestType=""GUI""><Name>Convert multiple numbers to strings</Name><CommandLine>Examp2.EXE /Verbose</CommandLine><Input>123</Input><Output>One Two Three</Output></Test><Test TestId=""0004"" TestType=""GUI""><Name>Find correlated key</Name><CommandLine>Examp3.EXE</CommandLine><Input>a1</Input><Output>b1</Output></Test><Test TestId=""0005"" TestType=""GUI""><Name>Count characters</Name><CommandLine>FinalExamp.EXE</CommandLine><Input>This is a test</Input><Output>14</Output></Test><Test TestId=""0006"" TestType=""GUI""><Name>Another Test</Name><CommandLine>Examp2.EXE</CommandLine><Input>Test Input</Input><Output>10</Output></Test><Signature Id=""id-sig-etsi-signed-xml"" xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"" /><Reference Id=""id-ref-sig-etsi-signed-signature""><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>LmhIrC01+dolxjYXvlCkijJNZ7GbyppRY4pz2m10DUE=</DigestValue></Reference><Reference Id=""id-ref-sig-etsi-signed-signature-xml"" URI=""""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>pHU116CJlKfwxSm8sHge6mYznqLapL0u/tCk5HnW8c8=</DigestValue></Reference><Reference URI=""#id-xades-signed-properties"" Type=""http://uri.etsi.org/01903#SignedProperties""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>rPyJxcqcfFZjn5LKPTptPryuTCUg21ZpSrPnoOERymk=</DigestValue></Reference></SignedInfo><SignatureValue>laQhcQvjEcPYzW76ZCtjZR49UswXzn4zFCKL3u+GrlAhBfjHHjt4O+N1dUDiWtQ3NSmnGc94+lOpZ2+cs94WdA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIC7zCCAnagAwIBAgIBJDAKBggqhkjOPQQDAzBxMQswCQYDVQQGEwJCRzETMBEGA1UECAwKU29maWEtZ3JhZDEOMAwGA1UEBwwFU29maWExFDASBgNVBAoMC0ludGVybmFsLUNBMREwDwYDVQQLDAhTb2Z0d2FyZTEUMBIGA1UEAwwLSW50ZXJuYWwtQ0EwHhcNMjMwNDAxMTc0NzE4WhcNMjgwMzMxMTc0NzE4WjCBhTELMAkGA1UEBhMCQkcxDjAMBgNVBAgMBVNvZmlhMR8wHQYDVQQKDBZHbG9iYWwgQ29uc3VsdGluZyBMdGQuMSEwHwYDVQQDDBhBbGVrc2FuZGFyIEl2YW5vdiBHeW9ub3YxIjAgBgkqhkiG9w0BCQEWE3RhenpAZ2xvYmFsY29ucy5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASWGh3gQuwVkZqRvuklH7Zf2li1+AeuDDgtkpm2tz0c5M9mFHelFSxFhCUADAT60UY+zxGH0Q9jhck54G3T3cXgo4HpMIHmMAkGA1UdEwQCMAAwHQYDVR0OBBYEFGVePyNTSQHUViultA676zdcPLXhMB8GA1UdIwQYMBaAFAU8b+ZWqLu1Txm/BAJt3bdosCOqMAsGA1UdDwQEAwID+DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDAwYIKwYBBQUHAwgwTwYDVR0RBEgwRoISd3d3Lmdsb2JhbGNvbnMuY29tghAqLmdsb2JhbGNvbnMuY29tgglsb2NhbGhvc3SBE3RhenpAZ2xvYmFsY29ucy5jb20wCgYIKoZIzj0EAwMDZwAwZAIwZ/4wM11j20AlPeMdTLWrHh1ed0SjNBjv+Apu5x9R8sI7THuQlrBh6qnw9jG9T/4AAjBTioezR1g8JhKSvjy139U4G9i/drqTP5isdAX4W7msJrdzmti7Tyo3r1N8wIlDW3k=</X509Certificate></X509Data></KeyInfo><Object><xades:QualifyingProperties xmlns:xades=""http://uri.etsi.org/01903/v1.3.2#"" Target=""#id-sig-etsi-signed-xml""><xades:SignedProperties Id=""id-xades-signed-properties""><xades:SignedSignatureProperties><xades:SigningTime>2023-04-09T12:59:30Z</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha512"" /><DigestValue>4BDAHqGY3KJZEqvMwCysPpTeaLOMkTTtRpSY7vv4yJ7d66Q0mK0+voqDxrV/nLd5/FmCQRhCIX4Rxr0fTe69jw==</DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties><xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference=""#id-ref-sig-etsi-signed-signature""><xades:MimeType>application/octet-stream</xades:MimeType></xades:DataObjectFormat><xades:DataObjectFormat ObjectReference=""#id-ref-sig-etsi-signed-signature-xml""><xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties></xades:QualifyingProperties></Object></Signature></Tests>";

    [Fact(DisplayName = "Test XML RSA with enveloped data")]
    public void Test_XML_RSA_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Get payload 
            var doc = new XmlDocument();
            doc.LoadXml(message.Trim());

            // Create signer 
            ETSISignedXml signer = new ETSISignedXml(rsaKey, HashAlgorithmName.SHA512);

            // Sign payload
            XmlElement signature = signer.Sign(doc, cert);

            // Prepare enveloped data
            doc.DocumentElement!.AppendChild(doc.ImportNode(signature, true));

            // Verify signature
            Assert.True(signer.Verify(doc, out ETSIContextInfo cInfo) 
                        && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                        && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test XML RSA with detached data")]
    public void Test_XML_RSA_Detached()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim()), false))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISignedXml signer = new ETSISignedXml(rsaKey, HashAlgorithmName.SHA512);

                // Sign payload
                XmlElement signature = signer.SignDetached(ms, cert);

                // Prepare enveloped data
                var doc = new XmlDocument();
                doc.LoadXml(signature.OuterXml);

                // Verify signature
                Assert.True(signer.VerifyDetached(msCheck, doc, out ETSIContextInfo cInfo)
                        && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                        && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value));
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test XML RSA with detached data and enveloped XML")]
    public void Test_XML_RSA_Detached_And_Eveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim())))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()))) {
                // Get XML payload 
                var doc = new XmlDocument();
                doc.LoadXml(message.Trim());

                // Create signer 
                ETSISignedXml signer = new ETSISignedXml(rsaKey, HashAlgorithmName.SHA512);

                // Sign payload
                XmlElement signature = signer.SignDetached(ms, cert, doc);

                // Prepare enveloped data
                doc.DocumentElement!.AppendChild(doc.ImportNode(signature, true));

                // Verify signature
                Assert.True(signer.VerifyDetached(msCheck, doc, out ETSIContextInfo cInfo)
                        && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                        && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value));
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test XML RSA with enveloped data and TimeStamp")]
    public async Task Test_XML_RSA_Enveloped_Timestamped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Get payload 
            var doc = new XmlDocument();
            doc.LoadXml(message.Trim());

            // Create signer 
            ETSISignedXml signer = new ETSISignedXml(rsaKey, HashAlgorithmName.SHA512);

            // Sign payload
            XmlElement signature = signer.Sign(doc, cert);

            // Prepare enveloped data
            doc.DocumentElement!.AppendChild(doc.ImportNode(signature, true));

            // Add timestamp
            await signer.AddTimestampAsync(CreateRfc3161RequestAsync, doc);

            // Verify signature
            Assert.True(signer.Verify(doc, out ETSIContextInfo cInfo)
                        && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                        && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test XML ECDSA with enveloped data")]
    public void Test_XML_ECDSA_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDSA certificate available");
        }

        // Get RSA private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Get payload 
            var doc = new XmlDocument();
            doc.LoadXml(message.Trim());

            // Create signer 
            ETSISignedXml signer = new ETSISignedXml(ecKey, HashAlgorithmName.SHA256);

            // Sign payload
            XmlElement signature = signer.Sign(doc, cert);

            // Prepare enveloped data
            doc.DocumentElement!.AppendChild(doc.ImportNode(signature, true));

            // Verify signature
            Assert.True(signer.Verify(doc, out ETSIContextInfo cInfo)
                        && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                        && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value));
        } else {
            Assert.Fail("NO ECDSA certificate available");
        }
    }

    [Fact(DisplayName = "Test XML ECDSA with detached data")]
    public void Test_XML_ECDSA_Detached()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDSA certificate available");
        }

        // Get  private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim()), false))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISignedXml signer = new ETSISignedXml(ecKey);

                // Sign payload
                XmlElement signature = signer.SignDetached(ms, cert);

                // Prepare enveloped data
                var doc = new XmlDocument();
                doc.LoadXml(signature.OuterXml);

                // Verify signature
                Assert.True(signer.VerifyDetached(msCheck, doc, out ETSIContextInfo cInfo)
                        && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                        && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value));
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test XML ECDSA with detached data and enveloped XML")]
    public void Test_XML_ECDSA_Detached_And_Eveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim())))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()))) {
                // Get XML payload 
                var doc = new XmlDocument();
                doc.LoadXml(message.Trim());

                // Create signer 
                ETSISignedXml signer = new ETSISignedXml(ecKey);

                // Sign payload
                XmlElement signature = signer.SignDetached(ms, cert, doc);

                // Prepare enveloped data
                doc.DocumentElement!.AppendChild(doc.ImportNode(signature, true));

                // Verify signature
                Assert.True(signer.VerifyDetached(msCheck, doc, out ETSIContextInfo cInfo)
                        && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                        && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value));
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test XML ECDSA with detached data and enveloped XML - malformed")]
    public void Test_XML_ECDSA_Detached_And_Eveloped_Malformed()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim())))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFileTwo.Trim()))) {
                // Get XML payload 
                var doc = new XmlDocument();
                doc.LoadXml(message.Trim());
                var docTwo = new XmlDocument();
                docTwo.LoadXml(malformedSign.Trim());

                // Create signer 
                ETSISignedXml signer = new ETSISignedXml(ecKey);

                // Sign payload
                XmlElement signature = signer.SignDetached(ms, cert, doc);

                // Prepare enveloped data
                doc.DocumentElement!.AppendChild(doc.ImportNode(signature, true));

                // Verify signature
                Assert.False(signer.VerifyDetached(msCheck, docTwo, out ETSIContextInfo cInfo)
                        && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                        && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value));
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    // Get some certificate from the store for testing
    private static X509Certificate2? GetCertificate(CertType certType)
    {
        var now = DateTime.Now;
        using (X509Store store = new X509Store(StoreLocation.CurrentUser)) {
            store.Open(OpenFlags.ReadOnly);

            var coll = store.Certificates
                            .Where(cert => cert.HasPrivateKey && cert.NotBefore < now && cert.NotAfter > now)
                            .ToList();

            List<X509Certificate2> valColl = new List<X509Certificate2>();

            foreach (var c in coll) {
                using (var chain = new X509Chain()) {

                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.DisableCertificateDownloads = true;
                    if (chain.Build(c)) {
                        valColl.Add(c);
                    } else {
                        c.Dispose();
                    }

                    for (int i = 0; i < chain.ChainElements.Count; i++) {
                        chain.ChainElements[i].Certificate.Dispose();
                    }
                }
            }

            return valColl.Where(c =>
            {
                string frName = certType switch
                {
                    CertType.RSA => "RSA",
                    CertType.EC => "ECC",
                    _ => "Ed"
                };
                return c.PublicKey.Oid.FriendlyName == frName;
            })
            .FirstOrDefault();
        }
    }

    private async Task<byte[]> CreateRfc3161RequestAsync(byte[] data, CancellationToken ct = default)
    {
        Rfc3161TimestampRequest req = Rfc3161TimestampRequest.CreateFromData(data, HashAlgorithmName.SHA512, null, null, true, null);

        using (HttpClient client = new HttpClient()) {
            client.DefaultRequestHeaders.Accept.Clear();

            HttpContent content = new ByteArrayContent(req.Encode());

            content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

            // "http://timestamp.sectigo.com/qualified"
            // "http://tsa.esign.bg"
            // "http://timestamp.digicert.com"
            var res = await client.PostAsync("http://timestamp.sectigo.com/qualified", content, ct);


            return (await res.Content.ReadAsByteArrayAsync(ct))[9..]; // 9 // 27 // 9
        }
    }
}
