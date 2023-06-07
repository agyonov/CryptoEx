
using CryptoEx.Ed.EdDsa;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.Tests;
public class TestEdDsaExtentions
{
    [Fact(DisplayName = "Get public key from Crt/Cer File")]
    public void TestGetPublicKeyFromCrt()
    {
        using (FileStream fs = File.Open(@"c:\temp\cert.crt", FileMode.Open, FileAccess.Read)) {
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
        using (FileStream fs = File.Open(@"c:\temp\cert.pfx", FileMode.Open, FileAccess.Read)) {
            X509Certificate2Ed[] certs = fs.LoadEdCertificatesFromPfx("pass.123");

            // Check
            Assert.NotEmpty(certs);

            // Get private key
            EdDsa? edDsa = certs[0].GetEdDsaPrivateKey();

            // Check
            Assert.NotNull(edDsa);
        }
    }
}
