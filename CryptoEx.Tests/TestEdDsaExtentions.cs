
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
        using (FileStream fs = File.Open(@"source\cert.pfx", FileMode.Open, FileAccess.Read)) {
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

    [Fact(DisplayName = "Get private key from PEM and sign")]
    public void TestGetPrivateKeyFromPemAndSign()
    {
        // Create EdDsa
        EdDsa edDsa = EdDsa.Create();

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\cert.key", FileMode.Open, FileAccess.Read))
        using (StreamReader sr = new (fs)) {
            // Import
            edDsa.ImportFromPem(sr.ReadToEnd());

            // Sign
            byte[] signature = edDsa.Sign(System.Text.Encoding.UTF8.GetBytes(testMessage));

            // Get signature as hex string
            string signatureHex = PemEd.ByteToHex(signature);

            // Check
            Assert.Equal(signature25519, signatureHex);
        }
    }

    [Fact(DisplayName = "Get private key from encrypted PEM and sign")]
    public void TestGetPrivateKeyFromPemEncriptedAndSign()
    {
        // Create EdDsa
        EdDsa edDsa = EdDsa.Create();

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\cert.pem", FileMode.Open, FileAccess.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDsa.ImportFromEncryptedPem(sr.ReadToEnd(), "pass.123");

            // Sign
            byte[] signature = edDsa.Sign(System.Text.Encoding.UTF8.GetBytes(testMessage));

            // Get signature as hex string
            string signatureHex = PemEd.ByteToHex(signature);

            // Check
            Assert.Equal(signature25519, signatureHex);
        }
    }

    [Fact(DisplayName = "Get public key from PEM and verify")]
    public void TestGetPublicKeyFromPemAndVerify()
    {
        // Create EdDsa
        EdDsa edDsa = EdDsa.Create();

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\cert.pub", FileMode.Open, FileAccess.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDsa.ImportFromPem(sr.ReadToEnd());

            // Verify
            bool result = edDsa.Verify(System.Text.Encoding.UTF8.GetBytes(testMessage), PemEd.HexToByte(signature25519));

            // Check
            Assert.True(result);
        }
    }

    [Fact(DisplayName = "Get public key 448 from Crt/Cer File")]
    public void TestGetPublicKey448FromCrt()
    {
        using (FileStream fs = File.Open(@"source\cert448.crt", FileMode.Open, FileAccess.Read)) {
            X509Certificate2? cert = fs.LoadEdCertificateFromCrt();

            // Check
            Assert.NotNull(cert);

            // Get public key
            EdDsa? edDsa = cert.GetEdDsaPublicKey();

            // Check
            Assert.NotNull(edDsa);
        }
    }

    [Fact(DisplayName = "Get private key 448 from Pfx/P12 File")]
    public void TestGetPrivateKey448FromPfx()
    {
        using (FileStream fs = File.Open(@"source\cert448.pfx", FileMode.Open, FileAccess.Read)) {
            X509Certificate2Ed[] certs = fs.LoadEdCertificatesFromPfx("pass.123");

            // Check
            Assert.NotEmpty(certs);

            // Get private key
            EdDsa? edDsa = certs[0].GetEdDsaPrivateKey();

            // Check
            Assert.NotNull(edDsa);
        }
    }

    [Fact(DisplayName = "Sign with private key 448 from pfx")]
    public void TestSign448()
    {
        using (FileStream fs = File.Open(@"source\cert448.pfx", FileMode.Open, FileAccess.Read)) {
            X509Certificate2Ed[] certs = fs.LoadEdCertificatesFromPfx("pass.123");

            // Check
            Assert.NotEmpty(certs);

            // Get private key
            EdDsa? edDsa = certs[0].GetEdDsaPrivateKey();

            // Check
            Assert.NotNull(edDsa);

            // Sign
            byte[] signature = edDsa.Sign(System.Text.Encoding.UTF8.GetBytes(testMessage448));

            // Get signature as hex string
            string signatureHex = PemEd.ByteToHex(signature);

            // Check
            Assert.Equal(signature448, signatureHex);
        }
    }

    [Fact(DisplayName = "Verify with public key 448 from crt")]
    public void TestVerify448()
    {
        using (FileStream fs = File.Open(@"source\cert448.crt", FileMode.Open, FileAccess.Read)) {
            X509Certificate2? cert = fs.LoadEdCertificateFromCrt();

            // Check
            Assert.NotNull(cert);

            // Get public key
            EdDsa? edDsa = cert.GetEdDsaPublicKey();

            // Check
            Assert.NotNull(edDsa);

            // Verify
            bool result = edDsa.Verify(System.Text.Encoding.UTF8.GetBytes(testMessage448), PemEd.HexToByte(signature448));

            // Check
            Assert.True(result);
        }
    }

    [Fact(DisplayName = "Get private key 448 from PEM and sign")]
    public void TestGetPrivateKey448FromPemAndSign()
    {
        // Create EdDsa
        EdDsa edDsa = EdDsa.Create();

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\cert448.key", FileMode.Open, FileAccess.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDsa.ImportFromPem(sr.ReadToEnd());

            // Sign
            byte[] signature = edDsa.Sign(System.Text.Encoding.UTF8.GetBytes(testMessage448));

            // Get signature as hex string
            string signatureHex = PemEd.ByteToHex(signature);

            // Check
            Assert.Equal(signature448, signatureHex);
        }
    }

    [Fact(DisplayName = "Get private key 448 from encrypted PEM and sign")]
    public void TestGetPrivateKey448FromPemEncriptedAndSign()
    {
        // Create EdDsa
        EdDsa edDsa = EdDsa.Create();

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\cert448.pem", FileMode.Open, FileAccess.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDsa.ImportFromEncryptedPem(sr.ReadToEnd(), "pass.123");

            // Sign
            byte[] signature = edDsa.Sign(System.Text.Encoding.UTF8.GetBytes(testMessage448));

            // Get signature as hex string
            string signatureHex = PemEd.ByteToHex(signature);

            // Check
            Assert.Equal(signature448, signatureHex);
        }
    }

    [Fact(DisplayName = "Get public key 448 from PEM and verify")]
    public void TestGetPublicKey448FromPemAndVerify()
    {
        // Create EdDsa
        EdDsa edDsa = EdDsa.Create();

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\cert448.pub", FileMode.Open, FileAccess.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDsa.ImportFromPem(sr.ReadToEnd());

            // Verify
            bool result = edDsa.Verify(System.Text.Encoding.UTF8.GetBytes(testMessage448), PemEd.HexToByte(signature448));

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

    // Ed448 private key from OpenSSL
    //  "625D3EDEB5CD69B20B0B6387C3522A21D356AC40B408E34FB2F8442E2C91EEE3F877AFE583A2FD11770567DF69178019D6FBC6357C35EEFA3E";
    // Ed448 public key from OpenSSL
    //  "261D23911E194ED0CB7F9233568E906D6ABCF4D60F73451CA807636D8FA6E4EA5CA12F51D240299A0B86A61CCB2174CE4ED2A8C4F7A8CCED00";
    // Some test message
    public const string testMessage448 = "Message for Ed448 signing";
    // Signature of the test message from OpenSSL
    public const string signature448 = "5114674F1CE8A2615F2B15138944E5C58511804D72A96260CE8C587E7220DAA90B9E65B450FF49563744D7633B43A78B8DC6EC3E3397B50080A15F06CE8005AD817A1681A4E96EE6B4831679EF448D7C283B188ED64D399D6BAC420FADF33964B2F2E0F2D1ABD401E8EB09AB29E3FF280600";
}
