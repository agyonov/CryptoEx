using CryptoEx.Ed;
using CryptoEx.XML.ETSI;
using SysadminsLV.PKI.OcspClient;
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

    public static string externallySigned = """
        <?xml version="1.0" encoding="UTF-8" standalone="no"?>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="id-3707dd0a07843f593c538d26b40b3491">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference Id="r-id-3707dd0a07843f593c538d26b40b3491-1" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#o-r-id-3707dd0a07843f593c538d26b40b3491-1">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>BmJipdHHC75mWOtb7k9P2HcrW30MwrZB+LAtoJ0z1VM=</ds:DigestValue>
                </ds:Reference>
                <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xades-id-3707dd0a07843f593c538d26b40b3491">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>XZWoaebRQTjKfqyKh5tW20U8tvSnMYTcXfWreGjE4Bo=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue Id="value-id-3707dd0a07843f593c538d26b40b3491">tU7ER5+Zrn3PPakt8GxMKO4y8JtACdHnnJMQyN2cHDk5a05XGVJRT0vqxzn1iT3zR2puXEknK8/fHZ737/KZQbvmkWu8IPoPQUbMCvFxlV7hD3ihmRESibBZ+6g8Z4h3RG0qWHp9EKE1SNA1XrQK/ueokzYl/fIRAYav5SEeOxKpSS18CEzuXs2BZCkyWrTx1XxUa/6ehZ+kic7b3xx45mBWD3lrm40RsZCN+m+W+mmuPV8h+bv4pRA8wcn2WhXlkDxHoi1E/BiZ0NQPo3Th/9VOBO8O10FgJA2uObOTqXPWMhZ2WBedfULQQqLmIYogI56pzonVaQBxHT7qP7Q4Aw==</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>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</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
            <ds:Object>
                <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#id-3707dd0a07843f593c538d26b40b3491">
                    <xades:SignedProperties Id="xades-id-3707dd0a07843f593c538d26b40b3491">
                        <xades:SignedSignatureProperties>
                            <xades:SigningTime>2023-06-01T08:37:30Z</xades:SigningTime>
                            <xades:SigningCertificateV2>
                                <xades:Cert>
                                    <xades:CertDigest>
                                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                                        <ds:DigestValue>Qe3PjAZkz4NyHfbMijQqaDeBUrkS6TvGEB28em416ctpz7QYfzD4CbuElSJl/Lil/CK4qcX73/hEue7K5SIqPw==</ds:DigestValue>
                                    </xades:CertDigest>
                                    <xades:IssuerSerialV2>MIGIMHykejB4MQswCQYDVQQGEwJCRzEYMBYGA1UEYRMPTlRSQkctMjAxMjMwNDI2MRIwEAYDVQQKEwlCT1JJQ0EgQUQxEDAOBgNVBAsTB0ItVHJ1c3QxKTAnBgNVBAMTIEItVHJ1c3QgT3BlcmF0aW9uYWwgUXVhbGlmaWVkIENBAggRdKeknkJNzg==</xades:IssuerSerialV2>
                                </xades:Cert>
                            </xades:SigningCertificateV2>
                        </xades:SignedSignatureProperties>
                        <xades:SignedDataObjectProperties>
                            <xades:DataObjectFormat ObjectReference="#r-id-3707dd0a07843f593c538d26b40b3491-1">
                                <xades:MimeType>text/xml</xades:MimeType>
                            </xades:DataObjectFormat>
                        </xades:SignedDataObjectProperties>
                    </xades:SignedProperties>
                </xades:QualifyingProperties>
            </ds:Object>
            <ds:Object Id="o-r-id-3707dd0a07843f593c538d26b40b3491-1">PFRlc3RzIHhtbG5zPSJodHRwOi8vd3d3LmFkYXR1bS5jb20iPg0KICAgIDxUZXN0IFRlc3RJZD0iMDAwMSIgVGVzdFR5cGU9IkNNRCI+DQogICAgICAgIDxOYW1lPkNvbnZlcnQgbnVtYmVyIHRvIHN0cmluZzwvTmFtZT4NCiAgICAgICAgPENvbW1hbmRMaW5lPkV4YW1wMS5FWEU8L0NvbW1hbmRMaW5lPg0KICAgICAgICA8SW5wdXQ+MTwvSW5wdXQ+DQogICAgICAgIDxPdXRwdXQ+T25lPC9PdXRwdXQ+DQogICAgPC9UZXN0Pg0KICAgIDxUZXN0IFRlc3RJZD0iMDAwMiIgVGVzdFR5cGU9IkNNRCI+DQogICAgICAgIDxOYW1lPkZpbmQgc3VjY2VlZGluZyBjaGFyYWN0ZXJzPC9OYW1lPg0KICAgICAgICA8Q29tbWFuZExpbmU+RXhhbXAyLkVYRTwvQ29tbWFuZExpbmU+DQogICAgICAgIDxJbnB1dD5hYmM8L0lucHV0Pg0KICAgICAgICA8T3V0cHV0PmRlZjwvT3V0cHV0Pg0KICAgIDwvVGVzdD4NCiAgICA8VGVzdCBUZXN0SWQ9IjAwMDMiIFRlc3RUeXBlPSJHVUkiPg0KICAgICAgICA8TmFtZT5Db252ZXJ0IG11bHRpcGxlIG51bWJlcnMgdG8gc3RyaW5nczwvTmFtZT4NCiAgICAgICAgPENvbW1hbmRMaW5lPkV4YW1wMi5FWEUgL1ZlcmJvc2U8L0NvbW1hbmRMaW5lPg0KICAgICAgICA8SW5wdXQ+MTIzPC9JbnB1dD4NCiAgICAgICAgPE91dHB1dD5PbmUgVHdvIFRocmVlPC9PdXRwdXQ+DQogICAgPC9UZXN0Pg0KICAgIDxUZXN0IFRlc3RJZD0iMDAwNCIgVGVzdFR5cGU9IkdVSSI+DQogICAgICAgIDxOYW1lPkZpbmQgY29ycmVsYXRlZCBrZXk8L05hbWU+DQogICAgICAgIDxDb21tYW5kTGluZT5FeGFtcDMuRVhFPC9Db21tYW5kTGluZT4NCiAgICAgICAgPElucHV0PmExPC9JbnB1dD4NCiAgICAgICAgPE91dHB1dD5iMTwvT3V0cHV0Pg0KICAgIDwvVGVzdD4NCiAgICA8VGVzdCBUZXN0SWQ9IjAwMDUiIFRlc3RUeXBlPSJHVUkiPg0KICAgICAgICA8TmFtZT5Db3VudCBjaGFyYWN0ZXJzPC9OYW1lPg0KICAgICAgICA8Q29tbWFuZExpbmU+RmluYWxFeGFtcC5FWEU8L0NvbW1hbmRMaW5lPg0KICAgICAgICA8SW5wdXQ+VGhpcyBpcyBhIHRlc3Q8L0lucHV0Pg0KICAgICAgICA8T3V0cHV0PjE0PC9PdXRwdXQ+DQogICAgPC9UZXN0Pg0KICAgIDxUZXN0IFRlc3RJZD0iMDAwNiIgVGVzdFR5cGU9IkdVSSI+DQogICAgICAgIDxOYW1lPkFub3RoZXIgVGVzdDwvTmFtZT4NCiAgICAgICAgPENvbW1hbmRMaW5lPkV4YW1wMi5FWEU8L0NvbW1hbmRMaW5lPg0KICAgICAgICA8SW5wdXQ+VGVzdCBJbnB1dDwvSW5wdXQ+DQogICAgICAgIDxPdXRwdXQ+MTA8L091dHB1dD4NCiAgICA8L1Rlc3Q+DQo8L1Rlc3RzPg==</ds:Object>
        </ds:Signature>
     """;

    [Fact(DisplayName = "Test XML RSA with externally signed data")]
    public void Test_XML_RSA_Externally_Signed()
    {

        // Get payload 
        var doc = new XmlDocument();
        doc.LoadXml(externallySigned.Trim());

        // Create signer 
        ETSISignedXml signer = new();

        // Verify signature
        Assert.True(signer.Verify(doc, out ETSIContextInfo cInfo)
                    && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                    && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value));
    }

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

    [Fact(DisplayName = "Test XML RSA with enveloping data")]
    public void Test_XML_RSA_Enveloping()
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
            XmlElement signature = signer.SignEnveloping(doc, cert);

            // Prepare to verify
            doc.LoadXml(signature.OuterXml);

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

    [Fact(DisplayName = "Test XML ECDSA with enveloping data")]
    public void Test_XML_ECDSA_Enveloping()
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
            ETSISignedXml signer = new ETSISignedXml(ecKey, HashAlgorithmName.SHA512);

            // Sign payload
            XmlElement signature = signer.SignEnveloping(doc, cert);

            // Prepare to verify
            doc.LoadXml(signature.OuterXml);

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

    [Fact(DisplayName = "Test XML RSA with enveloped data and TimeStamp LTA")]
    public async Task Test_XML_RSA_Enveloped_Timestamped_LTA()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificateOnWindows(CertType.RSA, out X509Certificate2[] issuers);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get some more certificates
        X509Certificate2[] timeStampCerts = GetCertificatesTimeStamp();

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

            // UP TO HERE WE HAVE BASELINE T !!!

            // Get OCSPs for the signer
            List<byte[]> ocsps = GetOCSPs(cert, issuers);

            // Get OCSPs for the timestamp
            List<byte[]> ts_ocsp = [];
            if (_TS_x509Certificate2s != null) {
                var ls_ts = _TS_x509Certificate2s.ToList();
                ls_ts.AddRange(timeStampCerts);
                X509Certificate2[] tsCerts = ls_ts.ToArray();
                if (tsCerts.Length > 1) {
                    ts_ocsp = GetOCSPs(tsCerts[0], tsCerts[1..]);
                } else if (tsCerts.Length > 0) {
                    ts_ocsp = GetOCSPs(tsCerts[0], Array.Empty<X509Certificate2>());
                }
            }

            // add all certs in one place
            X509Certificate2[] all = new X509Certificate2[issuers.Length + timeStampCerts.Length];
            issuers.CopyTo(all, 0);
            timeStampCerts.CopyTo(all, issuers.Length);

            // add all OCSPs in one place
            ocsps.AddRange(ts_ocsp);

            // Add validating material - chain certificates and timestamp root and OCSPs
            // NB! In the response of the timestamp server there shall be also a certificate chain
            signer.AddValidatingMaterial(doc, all, ocsps);

            // UP TO HERE WE HAVE BASELINE LT !!!

            // Add archive timestamp
            await signer.AddArchiveTimestampAsync(CreateRfc3161RequestAsync, doc);

            // UP TO HERE WE HAVE BASELINE LTA !!!

            // Verify signature
            Assert.True(signer.Verify(doc, out ETSIContextInfo cInfo)
                        && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                        && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    private static List<byte[]> GetOCSPs(X509Certificate2 cert, X509Certificate2[] issuers)
    {
        // Locals
        List<byte[]> res = new List<byte[]>();


        OCSPRequest req = new(cert);
        OCSPResponse? resp = req.SendRequest("POST");
        if (resp != null) {
            res.Add(resp.RawData);
        }

        foreach (var i in issuers) {
            try {
                OCSPRequest req2 = new(i);
                OCSPResponse? resp2 = req2.SendRequest("POST");
                if (resp2 != null) {
                    res.Add(resp2.RawData);
                }
            } catch (Exception) {
                // Ignore
            }
        }

        // return 
        return res;
    }

    // Get some certificate from Windows store for testing
    private static X509Certificate2? GetCertificateOnWindows(CertType certType, out X509Certificate2[] issuers)
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

                    for (int i = 1; i < chain.ChainElements.Count; i++) {
                        chain.ChainElements[i].Certificate.Dispose();
                    }
                }
            }

            X509Certificate2? cert = valColl.Where(c =>
            {
                string frName = certType switch
                {
                    CertType.RSA => "RSA",
                    CertType.EC => "ECC",
                    _ => "Ed"
                };
                return c.PublicKey.Oid.FriendlyName == frName && !c.Issuer.Contains("localhost");
            })
            .FirstOrDefault();

            // Set issuers - noone
            issuers = Array.Empty<X509Certificate2>();

            // Get issuers
            if (cert != null) {
                // Some 
                using (var chain = new X509Chain()) {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.DisableCertificateDownloads = true;
                    if (chain.Build(cert)) {
                        issuers = new X509Certificate2[chain.ChainElements.Count - 1];
                        for (int i = 1; i < chain.ChainElements.Count; i++) {
                            issuers[i - 1] = chain.ChainElements[i].Certificate;
                        }
                    }
                }
            }

            // return
            return cert;
        }
    }

    // Get some certificate from PFX store for testing
    private static X509Certificate2? GetCertificate(CertType certType)
    {
        // Check what we need
        switch (certType) {
            case CertType.RSA:
                return X509CertificateLoader.LoadPkcs12FromFile(@"source\cerRSA.pfx", "pass.123");
            case CertType.EC:
                return X509CertificateLoader.LoadPkcs12FromFile(@"source\cerECC.pfx", "pass.123");
            case CertType.Ed:
                using (FileStream fs = new(@"source\cert.pfx", FileMode.Open, FileAccess.Read, FileShare.Read)) {
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

    // Call Timestamp server
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

            // Get the response
            byte[] tsRes = (await res.Content.ReadAsByteArrayAsync(ct))[9..]; // 9 // 27 // 9

            // Try to decode
            if (Rfc3161TimestampToken.TryDecode(tsRes, out Rfc3161TimestampToken? rfcToken, out int bytesRead)) {
                // 
                if (rfcToken != null) {
                    SignedCms signedInfo = rfcToken.AsSignedCms();
                    _TS_x509Certificate2s = signedInfo.Certificates;
                }
            }

            return tsRes;
        }
    }
    private static X509Certificate2Collection? _TS_x509Certificate2s;

    private static X509Certificate2[] GetCertificatesIssuer()
    {
        // Check what we need
        return [X509CertificateLoader.LoadCertificateFromFile(@"source\issuer_root.crt")];
    }

    private static X509Certificate2[] GetCertificatesTimeStamp()
    {
        // Check what we need
        return [X509CertificateLoader.LoadCertificateFromFile(@"source\SectigoQualifiedTimeStampingRootR45.crt")];
    }
}
