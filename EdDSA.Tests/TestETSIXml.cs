using CryptoEx.XML.ETSI;
using System.Security.Cryptography;
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
            Assert.True(signer.Verify(doc, out cert) && cert != null);
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
                Assert.True(signer.VerifyDetached(msCheck, doc, out cert) && cert != null);
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
                Assert.True(signer.VerifyDetached(msCheck, doc, out cert) && cert != null);
            }
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
            Assert.True(signer.Verify(doc, out cert) && cert != null);
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
                Assert.True(signer.VerifyDetached(msCheck, doc, out cert) && cert != null);
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
                Assert.True(signer.VerifyDetached(msCheck, doc, out cert) && cert != null);
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


}
