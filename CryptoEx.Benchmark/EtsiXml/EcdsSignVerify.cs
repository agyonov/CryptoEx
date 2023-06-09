using BenchmarkDotNet.Attributes;
using CryptoEx.Ed;
using CryptoEx.XML.ETSI;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace CryptoEx.Benchmark.EtsiXml;

[MemoryDiagnoser]
public class EcdsSignVerify
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

    public static string signedEnveloped = @"<Tests xmlns=""http://www.adatum.com""><Test TestId=""0001"" TestType=""CMD""><Name>Convert number to string</Name><CommandLine>Examp1.EXE</CommandLine><Input>1</Input><Output>One</Output></Test><Test TestId=""0002"" TestType=""CMD""><Name>Find succeeding characters</Name><CommandLine>Examp2.EXE</CommandLine><Input>abc</Input><Output>def</Output></Test><Test TestId=""0003"" TestType=""GUI""><Name>Convert multiple numbers to strings</Name><CommandLine>Examp2.EXE /Verbose</CommandLine><Input>123</Input><Output>One Two Three</Output></Test><Test TestId=""0004"" TestType=""GUI""><Name>Find correlated key</Name><CommandLine>Examp3.EXE</CommandLine><Input>a1</Input><Output>b1</Output></Test><Test TestId=""0005"" TestType=""GUI""><Name>Count characters</Name><CommandLine>FinalExamp.EXE</CommandLine><Input>This is a test</Input><Output>14</Output></Test><Test TestId=""0006"" TestType=""GUI""><Name>Another Test</Name><CommandLine>Examp2.EXE</CommandLine><Input>Test Input</Input><Output>10</Output></Test><Signature Id=""id-sig-etsi-signed-xml"" xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"" /><Reference Id=""id-ref-sig-etsi-signed-signature"" URI=""""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>pHU116CJlKfwxSm8sHge6mYznqLapL0u/tCk5HnW8c8=</DigestValue></Reference><Reference URI=""#id-xades-signed-properties"" Type=""http://uri.etsi.org/01903#SignedProperties""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>W9K5TTWu84oG4O1z1nw+F3JTZDjEF6ty25gJ5hA5UIc=</DigestValue></Reference></SignedInfo><SignatureValue>w5LFnllanEXYOYsNp7k5XszcZYW6n4CaU0J6nDON6qzmQuBoIc4B3JAUF1M4ZctVUEWJAYmXy0Z+FCKKcKMgzA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIC7zCCAnagAwIBAgIBJDAKBggqhkjOPQQDAzBxMQswCQYDVQQGEwJCRzETMBEGA1UECAwKU29maWEtZ3JhZDEOMAwGA1UEBwwFU29maWExFDASBgNVBAoMC0ludGVybmFsLUNBMREwDwYDVQQLDAhTb2Z0d2FyZTEUMBIGA1UEAwwLSW50ZXJuYWwtQ0EwHhcNMjMwNDAxMTc0NzE4WhcNMjgwMzMxMTc0NzE4WjCBhTELMAkGA1UEBhMCQkcxDjAMBgNVBAgMBVNvZmlhMR8wHQYDVQQKDBZHbG9iYWwgQ29uc3VsdGluZyBMdGQuMSEwHwYDVQQDDBhBbGVrc2FuZGFyIEl2YW5vdiBHeW9ub3YxIjAgBgkqhkiG9w0BCQEWE3RhenpAZ2xvYmFsY29ucy5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASWGh3gQuwVkZqRvuklH7Zf2li1+AeuDDgtkpm2tz0c5M9mFHelFSxFhCUADAT60UY+zxGH0Q9jhck54G3T3cXgo4HpMIHmMAkGA1UdEwQCMAAwHQYDVR0OBBYEFGVePyNTSQHUViultA676zdcPLXhMB8GA1UdIwQYMBaAFAU8b+ZWqLu1Txm/BAJt3bdosCOqMAsGA1UdDwQEAwID+DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDAwYIKwYBBQUHAwgwTwYDVR0RBEgwRoISd3d3Lmdsb2JhbGNvbnMuY29tghAqLmdsb2JhbGNvbnMuY29tgglsb2NhbGhvc3SBE3RhenpAZ2xvYmFsY29ucy5jb20wCgYIKoZIzj0EAwMDZwAwZAIwZ/4wM11j20AlPeMdTLWrHh1ed0SjNBjv+Apu5x9R8sI7THuQlrBh6qnw9jG9T/4AAjBTioezR1g8JhKSvjy139U4G9i/drqTP5isdAX4W7msJrdzmti7Tyo3r1N8wIlDW3k=</X509Certificate></X509Data></KeyInfo><Object><xades:QualifyingProperties xmlns:xades=""http://uri.etsi.org/01903/v1.3.2#"" Target=""#id-sig-etsi-signed-xml""><xades:SignedProperties Id=""id-xades-signed-properties""><xades:SignedSignatureProperties><xades:SigningTime>2023-04-10T07:38:04Z</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>N1atMU4w2QdnlN7a+IfoOiT68UwPwV0RuBcWpxniwN0=</DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties><xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference=""#id-ref-sig-etsi-signed-signature""><xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties></xades:QualifyingProperties></Object></Signature></Tests>";

    public static string signedDetached = @"<Signature Id=""id-sig-etsi-signed-xml"" xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"" /><Reference Id=""id-ref-sig-etsi-signed-signature""><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>pom9h9NK66ihYqyN/zdMG0Bo738UekEuAuCV2siXEUU=</DigestValue></Reference><Reference URI=""#id-xades-signed-properties"" Type=""http://uri.etsi.org/01903#SignedProperties""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>TNRUIKqzasjAVgLiO6YltRR9LuQ5m14RPb5aPdtwIb4=</DigestValue></Reference></SignedInfo><SignatureValue>0pGTtggaSAYf3qDoqMMD8cnEMDijJvWu7pUC8CWZ56crLAFD6Z6CrCsLlwNaSsq1Q3aL5SuqkoBWBZGfanzV9g==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIC7zCCAnagAwIBAgIBJDAKBggqhkjOPQQDAzBxMQswCQYDVQQGEwJCRzETMBEGA1UECAwKU29maWEtZ3JhZDEOMAwGA1UEBwwFU29maWExFDASBgNVBAoMC0ludGVybmFsLUNBMREwDwYDVQQLDAhTb2Z0d2FyZTEUMBIGA1UEAwwLSW50ZXJuYWwtQ0EwHhcNMjMwNDAxMTc0NzE4WhcNMjgwMzMxMTc0NzE4WjCBhTELMAkGA1UEBhMCQkcxDjAMBgNVBAgMBVNvZmlhMR8wHQYDVQQKDBZHbG9iYWwgQ29uc3VsdGluZyBMdGQuMSEwHwYDVQQDDBhBbGVrc2FuZGFyIEl2YW5vdiBHeW9ub3YxIjAgBgkqhkiG9w0BCQEWE3RhenpAZ2xvYmFsY29ucy5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASWGh3gQuwVkZqRvuklH7Zf2li1+AeuDDgtkpm2tz0c5M9mFHelFSxFhCUADAT60UY+zxGH0Q9jhck54G3T3cXgo4HpMIHmMAkGA1UdEwQCMAAwHQYDVR0OBBYEFGVePyNTSQHUViultA676zdcPLXhMB8GA1UdIwQYMBaAFAU8b+ZWqLu1Txm/BAJt3bdosCOqMAsGA1UdDwQEAwID+DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDAwYIKwYBBQUHAwgwTwYDVR0RBEgwRoISd3d3Lmdsb2JhbGNvbnMuY29tghAqLmdsb2JhbGNvbnMuY29tgglsb2NhbGhvc3SBE3RhenpAZ2xvYmFsY29ucy5jb20wCgYIKoZIzj0EAwMDZwAwZAIwZ/4wM11j20AlPeMdTLWrHh1ed0SjNBjv+Apu5x9R8sI7THuQlrBh6qnw9jG9T/4AAjBTioezR1g8JhKSvjy139U4G9i/drqTP5isdAX4W7msJrdzmti7Tyo3r1N8wIlDW3k=</X509Certificate></X509Data></KeyInfo><Object><xades:QualifyingProperties xmlns:xades=""http://uri.etsi.org/01903/v1.3.2#"" Target=""#id-sig-etsi-signed-xml""><xades:SignedProperties Id=""id-xades-signed-properties""><xades:SignedSignatureProperties><xades:SigningTime>2023-04-10T07:40:34Z</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha512"" /><DigestValue>4BDAHqGY3KJZEqvMwCysPpTeaLOMkTTtRpSY7vv4yJ7d66Q0mK0+voqDxrV/nLd5/FmCQRhCIX4Rxr0fTe69jw==</DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties><xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference=""#id-ref-sig-etsi-signed-signature""><xades:MimeType>application/octet-stream</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties></xades:QualifyingProperties></Object></Signature>";

    private XmlDocument docSource;
    private XmlDocument docSignedEnveloped;
    private XmlDocument docSignedDetached;
    private X509Certificate2? cert;

    public EcdsSignVerify()
    {
        docSource = new XmlDocument();
        docSource.LoadXml(message.Trim());
        docSignedEnveloped = new XmlDocument();
        docSignedEnveloped.LoadXml(signedEnveloped);
        docSignedDetached = new XmlDocument();
        docSignedDetached.LoadXml(signedDetached);
        cert = GetCertificate(CertType.EC);
        if (cert == null) {
            throw new Exception("No certificate found");
        }
    }

    [Benchmark]
    public void SignETSI_Enveloped()
    {
        // Get RSA private key
        ECDsa? ecKey = cert!.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Create signer 
            ETSISignedXml signer = new ETSISignedXml(ecKey, HashAlgorithmName.SHA256);

            // Sign payload
            _ = signer.Sign(docSource, cert!);
        } else {
            throw new Exception("NO ECDSA certificate available");
        }
    }

    [Benchmark]
    public void VerifyETSI_Enveloped()
    {
        // Create signer 
        ETSISignedXml signer = new ETSISignedXml();

        // Verify signature
        _ = signer.Verify(docSignedEnveloped, out ETSIContextInfo cInfo)
                    && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                    && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value);
    }

    [Benchmark]
    public void SignETSI_Detached()
    {
        // Get  private key
        ECDsa? ecKey = cert!.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISignedXml signer = new ETSISignedXml(ecKey);

                // Sign payload
                _ = signer.SignDetached(ms, cert!);
            }
        } else {
            throw new Exception("NO ECDSA certificate available");
        }
    }

    [Benchmark]
    public void VerifyETSI_Detached()
    {
        // Get payload 
        using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
            // Create signer 
            ETSISignedXml signer = new ETSISignedXml();

            // Verify signature
            _ = signer.VerifyDetached(msCheck, docSignedDetached, out ETSIContextInfo cInfo)
                    && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                    && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value);
        }
    }

    // Get some certificate from the store for testing
    private static X509Certificate2? GetCertificate(CertType certType)
    {
        //var now = DateTime.Now;
        //using (X509Store store = new X509Store(StoreLocation.CurrentUser)) {
        //    store.Open(OpenFlags.ReadOnly);

        //    var coll = store.Certificates
        //                    .Where(cert => cert.HasPrivateKey && cert.NotBefore < now && cert.NotAfter > now)
        //                    .ToList();

        //    List<X509Certificate2> valColl = new List<X509Certificate2>();

        //    foreach (var c in coll) {
        //        using (var chain = new X509Chain()) {

        //            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        //            chain.ChainPolicy.DisableCertificateDownloads = true;
        //            if (chain.Build(c)) {
        //                valColl.Add(c);
        //            } else {
        //                c.Dispose();
        //            }

        //            for (int i = 0; i < chain.ChainElements.Count; i++) {
        //                chain.ChainElements[i].Certificate.Dispose();
        //            }
        //        }
        //    }

        //    return valColl.Where(c =>
        //    {
        //        string frName = certType switch
        //        {
        //            CertType.RSA => "RSA",
        //            CertType.EC => "ECC",
        //            _ => "Ed"
        //        };
        //        return c.PublicKey.Oid.FriendlyName == frName;
        //    })
        //    .FirstOrDefault();
        //}

        // Check what we need
        switch (certType) {
            case CertType.RSA:
                return new X509Certificate2(@"source\cerRSA.pfx", "pass.123");
            case CertType.EC:
                return new X509Certificate2(@"source\cerECC.pfx", "pass.123");
            case CertType.Ed:
                using (FileStream fs = new(@"source\cert.pfx", FileMode.Open, FileAccess.Read)) {
                    X509Certificate2Ed[] arrCerts = fs.LoadEdCertificatesFromPfx("pass.123");
                    if (arrCerts.Length > 0) {
                        return arrCerts[0].Certificate;
                    } else {
                        return null;
                    }
                }
            default:
                return null;
        }
    }
}
