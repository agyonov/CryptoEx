
using CryptoEx.JWS;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using CryptoEx.Ed.EdDsa;
using Org.BouncyCastle.Security;
using CryptoEx.Ed.JWS;
using CryptoEx.Ed;

namespace CryptoEx.Tests;
public class TestETSIEdDSA
{
    // Some test data for JADES
    public static string message = """
    {
        "Разрешение": 2413413241243,
        "Име Латиница": "John Doe",
        "Име": "Джон Доу",
        "ЕГН/ЛНЧ": "1234567890",
        "Оръжия": [
            {
                "Сериен №": "98965049Ф769",
                "Модел": "AK-47"
            },
            {
                "Сериен №": "8984-3245",
                "Модел": "Барета"
            }
        ]
    }
    """;

    public static string testFile = """
    This is a test
    This is a test again
    """;

    [Fact(DisplayName = "Test JOSE EdDSA 25519 with enveloped data")]
    public void Test_JOSE_EdDsa_Enveloped()
    {
        // EdDSA key
        AsymmetricAlgorithm? privateKey = null;

        // Try get certificate
        X509Certificate2? cert = GetCertificate(out privateKey);
        if (cert == null) {
            Assert.Fail("NO EdDSA certificate available");
        }

        // Check EdDSA key
        if (privateKey != null && privateKey is EdDsa) {
            // Create signer 
            JWSSigner signer = new JWSSignerEd((EdDsa)privateKey);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] _);
            Assert.False(headers.Count != 1);
            var pubCertEnc = headers[0].X5c?.FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(pubCertEnc));
            var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
            Assert.NotNull(pubCert.GetEdDsaPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { pubCert.GetEdDsaPublicKey()! }, null));
        } else {
            Assert.Fail("NO EdDSA private key available");
        }
    }

    [Fact(DisplayName = "Test JOSE EdDSA 448 with enveloped data")]
    public void Test_JOSE_EdDsa_448_Enveloped()
    {
        // EdDSA key
        AsymmetricAlgorithm? privateKey = null;

        // Try get certificate
        X509Certificate2? cert = GetCertificate(out privateKey, EdAlgorithm.Ed448);
        if (cert == null) {
            Assert.Fail("NO EdDSA certificate available");
        }

        // Check EdDSA key
        if (privateKey != null && privateKey is EdDsa) {
            // Create signer 
            JWSSigner signer = new JWSSignerEd((EdDsa)privateKey);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] _);
            Assert.False(headers.Count != 1);
            var pubCertEnc = headers[0].X5c?.FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(pubCertEnc));
            var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
            Assert.NotNull(pubCert.GetEdDsaPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { pubCert.GetEdDsaPublicKey()! }, null));
        } else {
            Assert.Fail("NO EdDSA private key available");
        }
    }

    // Get certifacte from PFX store
    private static X509Certificate2? GetCertificate(out AsymmetricAlgorithm? privateKey, EdAlgorithm alg = EdAlgorithm.Ed25519)
    {
        // Ste initially
        privateKey = null;

        // Check what we need
        switch (alg) {
            case EdAlgorithm.Ed25519:
                using (FileStream fs = new(@"source\cert.pfx", FileMode.Open, FileAccess.Read)) {
                    X509Certificate2Ed[] arrCerts = fs.LoadEdCertificatesFromPfx("pass.123");
                    if (arrCerts.Length > 0) {
                        privateKey = arrCerts[0].PrivateKey;
                        return arrCerts[0].Certificate;
                    } else {
                        return null;
                    }
                }
            case EdAlgorithm.Ed448:
                using (FileStream fs = new(@"source\cert448.pfx", FileMode.Open, FileAccess.Read)) {
                    X509Certificate2Ed[] arrCerts = fs.LoadEdCertificatesFromPfx("pass.123");
                    if (arrCerts.Length > 0) {
                        privateKey = arrCerts[0].PrivateKey;
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
