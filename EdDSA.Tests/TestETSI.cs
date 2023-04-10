using CryptoEx.JOSE;
using CryptoEx.JOSE.ETSI;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoEx.Tests;
public class TestETSI
{
    public static readonly JsonSerializerOptions jsonOptions = new JsonSerializerOptions
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };


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

    [Fact(DisplayName = "Test JOSE RSA with enveloped data")]
    public void Test_JOSE_RSA_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Create signer 
            JWSSigner signer = new JWSSigner(rsaKey, HashAlgorithmName.SHA512);

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
            Assert.NotNull(pubCert.GetRSAPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { pubCert.GetRSAPublicKey()! }, null));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI RSA with enveloped data")]
    public void Test_ETSI_RSA_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Create signer 
            JWSSigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Compact);

            // Decode & verify
            var headers = signer.Decode<ETSIHeader>(jSign, out byte[] _);
            Assert.False(headers.Count != 1);
            var pubCertEnc = headers[0].X5c?.FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(pubCertEnc));
            var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
            Assert.NotNull(pubCert.GetRSAPublicKey());
            Assert.True(signer.Verify<ETSIHeader>(new AsymmetricAlgorithm[] { pubCert.GetRSAPublicKey()! }, ETSISigner.ETSIResolutor));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI RSA with detached data")]
    public void Test_ETSI_RSA_Detached()
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
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

                // Sign
                signer.AttachSignersCertificate(cert);
                signer.SignDetached(ms, mimeTypeAttachement: "text/plain");

                // Encode - produce JWS
                var jSign = signer.Encode(JWSEncodeTypeEnum.Full);

                // Decode & verify
                var headers = signer.Decode<ETSIHeader>(jSign, out byte[] _);
                Assert.False(headers.Count != 1);
                var pubCertEnc = headers[0].X5c?.FirstOrDefault();
                Assert.False(string.IsNullOrEmpty(pubCertEnc));
                var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
                Assert.NotNull(pubCert.GetRSAPublicKey());
                Assert.True(signer.VerifyDetached(msCheck, new AsymmetricAlgorithm[] { pubCert.GetRSAPublicKey()! }, headers));
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI RSA Timestamp with enveloped data")]
    public async Task Test_ETSI_RSA_Timestamp_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Create signer 
            ETSISigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");
            await signer.AddTimestampAsync(CreateRfc3161RequestAsync);
            Assert.True(signer.Encode(JWSEncodeTypeEnum.Flattened).Length > 0);
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI RSA Timestamp with detached data")]
    public async Task Test_ETSI_RSA_Timestamp_Detached()
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
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim()))) {
                // Create signer 
                ETSISigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

                // Sign 
                signer.AttachSignersCertificate(cert);
                signer.SignDetached(ms, message, "text/plain");
                await signer.AddTimestampAsync(CreateRfc3161RequestAsync);
                Assert.True(signer.Encode(JWSEncodeTypeEnum.Flattened).Length > 0);
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test JOSE ECDSA with enveloped data")]
    public void Test_JOSE_ECDSA_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDSA certificate available");
        }

        // Get RSA private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Create signer 
            JWSSigner signer = new JWSSigner(ecKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");
            Assert.True(signer.Encode().Length > 0);
        } else {
            Assert.Fail("NO ECDSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI ECDSA with enveloped data")]
    public void Test_ETSI_ECDSA_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDSA certificate available");
        }

        // Get RSA private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Create signer 
            JWSSigner signer = new ETSISigner(ecKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");
            Assert.True(signer.Encode(JWSEncodeTypeEnum.Flattened).Length > 0);
        } else {
            Assert.Fail("NO ECDSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI ECDSA Timestamp with enveloped data")]
    public async Task Test_ETSI_ECDSA_Timestamp_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDSA certificate available");
        }

        // Get RSA private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Create signer 
            ETSISigner signer = new ETSISigner(ecKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");
            await signer.AddTimestampAsync(CreateRfc3161RequestAsync);
            Assert.True(signer.Encode(JWSEncodeTypeEnum.Flattened).Length > 0);
        } else {
            Assert.Fail("NO ECDSA certificate available");
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
