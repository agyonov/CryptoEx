
using CryptoEx.Ed.EdDsa;
using CryptoEx.Ed.Utils;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.Tests;
public class TestEdDsaExtentions
{
    [Fact(DisplayName = "Get public key from Crt/Cer File")]
    public void TestGetPublicKeyFromCrt()
    {
        using (FileStream fs = File.Open(@"source\cert.crt", FileMode.Open, FileAccess.Read)) {
            X509Certificate2? cert = fs.LoadEdCertificateFromCrt();

            // Check
            Assert.NotNull(cert);

            // Get public key
            EdDsa? edDsa = cert.GetEdDsaPublicKey();

            // Check
            Assert.NotNull(edDsa);
        }
    }

    [Fact(DisplayName = "Get private key from Pfx/P12 File")]
    public void TestGetPrivateKeyFromPfx()
    {
        using (FileStream fs = File.Open(@"csource\cert.pfx", FileMode.Open, FileAccess.Read)) {
            X509Certificate2Ed[] certs = fs.LoadEdCertificatesFromPfx("pass.123");

            // Check
            Assert.NotEmpty(certs);

            // Get private key
            EdDsa? edDsa = certs[0].GetEdDsaPrivateKey();

            // Check
            Assert.NotNull(edDsa);
        }
    }

    [Fact(DisplayName = "Sign with private key from pfx")]
    public void TestSign() 
    {
        using (FileStream fs = File.Open(@"source\cert.pfx", FileMode.Open, FileAccess.Read)) {
            X509Certificate2Ed[] certs = fs.LoadEdCertificatesFromPfx("pass.123");

            // Check
            Assert.NotEmpty(certs);

            // Get private key
            EdDsa? edDsa = certs[0].GetEdDsaPrivateKey();

            // Check
            Assert.NotNull(edDsa);

            // Sign
            byte[] signature = edDsa.Sign(System.Text.Encoding.UTF8.GetBytes(testMessage));

            // Get signature as hex string
            string signatureHex = PemEd.ByteToHex(signature);

            // Check
            Assert.Equal(signature25519, signatureHex);
        }
    }

    [Fact(DisplayName = "Verify with public key from crt")]
    public void TestVerify()
    {
        using (FileStream fs = File.Open(@"source\cert.crt", FileMode.Open, FileAccess.Read)) {
            X509Certificate2? cert = fs.LoadEdCertificateFromCrt();

            // Check
            Assert.NotNull(cert);

            // Get public key
            EdDsa? edDsa = cert.GetEdDsaPublicKey();

            // Check
            Assert.NotNull(edDsa);

            // Verify
            bool result = edDsa.Verify(System.Text.Encoding.UTF8.GetBytes(testMessage), PemEd.HexToByte(signature25519));

            // Check
            Assert.True(result);
        }
    }

    // Ed25519 private key from OpenSSL
    //  "F4F3A94159C4BFF1A62642BE774E7C4E12F708C89C1FB643391E372DED84374E";
    // Ed25519 public key from OpenSSL
    //  "589E283430A6655608C591B898EAEECCE2A93F24B68C8018B20F1043F840FFDC";
    // Some test message
    public const string testMessage = "This is a test";
    // Signature of the test message from OpenSSL
    public const string signature25519 = "0F1CCF0EB3E2211ECFD5B1C078DB1E3F8AB0B4F7FEE624D98DC67B54F1D1B0C31E180A8D8C09D72097F44BC2BC93343935229BF2939ED2739B632CC454C47B01";
}
