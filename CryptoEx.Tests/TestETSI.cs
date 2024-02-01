using CryptoEx.Ed;
using CryptoEx.JWK;
using CryptoEx.JWS;
using CryptoEx.JWS.ETSI;
using Org.BouncyCastle.Crypto;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace CryptoEx.Tests;
public class TestETSI
{

    public static string HMACKey = """
    {
        "kty":"oct",
        "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    }
    """;

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

    [Fact(DisplayName = "Test JOSE RSA PSS with enveloped data")]
    public void Test_JOSE_RSA_PSS_Enveloped()
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
            JWSSigner signer = new JWSSigner(rsaKey, HashAlgorithmName.SHA512, true);

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
            ETSISigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json", JWSConstants.JOSE);

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Compact);

            // Decode & verify
            Assert.True(signer.Verify(jSign, out byte[] _, out ETSIContextInfo _));
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
                signer.SignDetached(ms, mimeTypeAttachement: "text/plain", typHeaderparameter: JWSConstants.JOSE_JSON);

                // Encode - produce JWS
                var jSign = signer.Encode(JWSEncodeTypeEnum.Flattened);

                // Decode & verify
                Assert.True(signer.VerifyDetached(msCheck, jSign, out byte[] payload, out ETSIContextInfo cInfo));
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

        // Get some more certificates
        X509Certificate2[] issuers = GetCertificatesIssuer();
        X509Certificate2[] timeStampCerts = GetCertificatesTimeStamp();

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Create signer 
            ETSISigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert, issuers);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json", JWSConstants.JOSE_JSON);
            await signer.AddTimestampAsync(CreateRfc3161RequestAsync);
            signer.AddValidatingMaterial(timeStampCerts);

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Full);

            // Decode & verify
            Assert.True(signer.Verify(jSign, out byte[] payload, out ETSIContextInfo cInfo));
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
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim())))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

                // Sign 
                signer.AttachSignersCertificate(cert);
                signer.SignDetached(ms, message, "text/plain", "text/json", JWSConstants.JOSE_JSON);
                await signer.AddTimestampAsync(CreateRfc3161RequestAsync);

                // Encode - produce JWS
                var jSign = signer.Encode(JWSEncodeTypeEnum.Full);

                // Decode & verify
                Assert.True(signer.VerifyDetached(msCheck, jSign, out byte[] payload, out ETSIContextInfo cInfo));
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
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json", JWSConstants.JOSE);

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] _);
            Assert.False(headers.Count != 1);
            var pubCertEnc = headers[0].X5c?.FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(pubCertEnc));
            var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
            Assert.NotNull(pubCert.GetECDsaPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { pubCert.GetECDsaPublicKey()! }, null));
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
            ETSISigner signer = new ETSISigner(ecKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json", JWSConstants.JOSE_JSON);

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Flattened);

            // Decode & verify
            Assert.True(signer.Verify(jSign, out byte[] _, out ETSIContextInfo _));
        } else {
            Assert.Fail("NO ECDSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI ECDSA with detached data")]
    public void Test_ETSI_ECDS_Detached()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDSA certificate available");
        }

        // Get ECDSA private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim())))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISigner signer = new ETSISigner(ecKey);

                // Sign
                signer.AttachSignersCertificate(cert);
                signer.SignDetached(ms, mimeTypeAttachement: "text/plain", typHeaderparameter: JWSConstants.JOSE_JSON);

                // Encode - produce JWS
                var jSign = signer.Encode(JWSEncodeTypeEnum.Flattened);

                // Decode & verify
                Assert.True(signer.VerifyDetached(msCheck, jSign, out byte[] payload, out ETSIContextInfo cInfo));
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI ECDSA with detached data asynchronious")]
    public async Task Test_ETSI_ECDS_Detached_Async()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDSA certificate available");
        }

        // Get ECDSA private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim())))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISigner signer = new ETSISigner(ecKey);

                // Sign
                signer.AttachSignersCertificate(cert);
                await signer.SignDetachedAsync(ms, mimeTypeAttachement: "text/plain", typHeaderparameter: JWSConstants.JOSE_JSON);

                // Encode - produce JWS
                var jSign = signer.Encode(JWSEncodeTypeEnum.Flattened);

                // Verify
                Assert.True(await signer.VerifyDetachedAsync(msCheck, jSign));
                // Decode - optionally
                ETSIContextInfo context = signer.ExtractContextInfo(jSign, out byte[] payload);

                // Verify certificate
                Assert.True(context.IsSigningCertificateValid ?? true);
                Assert.True(context.IsSigningCertDigestValid ?? true);
                Assert.True(context.IsSigningTimeInValidityPeriod ?? true);
            }
        } else {
            Assert.Fail("NO RSA certificate available");
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

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Flattened);

            // Decode & verify
            Assert.True(signer.Verify(jSign, out byte[] payload, out ETSIContextInfo cInfo));
        } else {
            Assert.Fail("NO ECDSA certificate available");
        }
    }

    [Fact(DisplayName = "Test JOSE HMAC with enveloped data")]
    public void Test_JOSE_HMAC_Enveloped()
    {
        // Try get Key
        JwkSymmetric? jwk = JsonSerializer.Deserialize<Jwk>(HMACKey, JwkConstants.jsonOptions) as JwkSymmetric;

        // Check
        Assert.NotNull(jwk);

        // Get The hkey
        byte[]? theKey = jwk.GetSymmetricKey();

        // Check
        Assert.NotNull(theKey);

        // Get The hkey
        using (HMAC key = new HMACSHA256(theKey)) {
            // Create signer 
            JWSSigner signer = new JWSSigner(key);

            // Get payload 
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] _);
            Assert.False(headers.Count != 1);
            Assert.True(signer.Verify<JWSHeader>(new HMAC[] { key }, null));
        }
    }

    [Fact(DisplayName = "Test JOSE RSA & HMAC with enveloped data")]
    public void Test_JOSE_RSA_HMAC_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Try get Key
        JwkSymmetric? jwk = JsonSerializer.Deserialize<Jwk>(HMACKey, JwkConstants.jsonOptions) as JwkSymmetric;

        // Check
        Assert.NotNull(jwk);

        // Get The hkey
        byte[]? theKey = jwk.GetSymmetricKey();

        // Check
        Assert.NotNull(theKey);

        // Get The hkey
        using (HMAC key = new HMACSHA256(theKey)) {
            // Create signer 
            JWSSigner signer = new JWSSigner(key);

            // Get payload 
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");

            // Sign with RSA
            signer.SetNewSigningKey(rsaKey, HashAlgorithmName.SHA512, true);
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Full);

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] _);
            Assert.False(headers.Count != 2);
            Assert.True(signer.Verify<JWSHeader>(new object[] { key, rsaKey }, null));
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

            return (await res.Content.ReadAsByteArrayAsync(ct))[9..]; // 9 // 27 // 9
        }
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
                return c.PublicKey.Oid.FriendlyName == frName;
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
                return new X509Certificate2(@"source\cerRSA.pfx", "pass.123");
            case CertType.EC:
                return new X509Certificate2(@"source\cerECC.pfx", "pass.123");
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

    private static X509Certificate2[] GetCertificatesIssuer()
    {
        // Check what we need
        return [new X509Certificate2(@"source\issuer_root.crt")];
    }

    private static X509Certificate2[] GetCertificatesTimeStamp()
    {
        // Check what we need
        return [new X509Certificate2(@"source\SectigoQualifiedTimeStampingRootR45.crt")];
    }
}
