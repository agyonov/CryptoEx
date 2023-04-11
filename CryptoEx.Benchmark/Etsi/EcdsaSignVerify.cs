using BenchmarkDotNet.Attributes;
using CryptoEx.JWS.ETSI;
using CryptoEx.XML.ETSI;
using Dia2Lib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace CryptoEx.Benchmark.Etsi;

[MemoryDiagnoser]
public class EcdsaSignVerify
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

    public static string signedEnveloped = @"{""payload"":""ew0KICAgICLQoNCw0LfRgNC10YjQtdC90LjQtSI6IDI0MTM0MTMyNDEyNDMsDQogICAgItCY0LzQtSDQm9Cw0YLQuNC90LjRhtCwIjogIkpvaG4gRG9lIiwNCiAgICAi0JjQvNC1IjogItCU0LbQvtC9INCU0L7RgyIsDQogICAgItCV0JPQnS_Qm9Cd0KciOiAiMTIzNDU2Nzg5MCIsDQogICAgItCe0YDRitC20LjRjyI6IFsNCiAgICAgICAgew0KICAgICAgICAgICAgItCh0LXRgNC40LXQvSDihJYiOiAiOTg5NjUwNDnQpDc2OSIsDQogICAgICAgICAgICAi0JzQvtC00LXQuyI6ICJBSy00NyINCiAgICAgICAgfSwNCiAgICAgICAgew0KICAgICAgICAgICAgItCh0LXRgNC40LXQvSDihJYiOiAiODk4NC0zMjQ1IiwNCiAgICAgICAgICAgICLQnNC-0LTQtdC7IjogItCR0LDRgNC10YLQsCINCiAgICAgICAgfQ0KICAgIF0NCn0"",""protected"":""eyJ0eXAiOiJqb3NlK2pzb24iLCJzaWdUIjoiMjAyMy0wNC0xMVQxMTo1NjoxMloiLCJjcml0IjpbInNpZ1QiXSwiYWxnIjoiRVMyNTYiLCJjdHkiOiJ0ZXh0L2pzb24iLCJraWQiOiJNSEV4Q3pBSkJnTlZCQVlUQWtKSE1STXdFUVlEVlFRSURBcFRiMlpwWVMxbmNtRmtNUTR3REFZRFZRUUhEQVZUYjJacFlURVVNQklHQTFVRUNnd0xTVzUwWlhKdVlXd3RRMEV4RVRBUEJnTlZCQXNNQ0ZOdlpuUjNZWEpsTVJRd0VnWURWUVFEREF0SmJuUmxjbTVoYkMxRFFRPT0iLCJ4NXQjUzI1NiI6Ik4xYXRNVTR3MlFkbmxON2EtSWZvT2lUNjhVd1B3VjBSdUJjV3B4bml3TjAiLCJ4NWMiOlsiTUlJQzd6Q0NBbmFnQXdJQkFnSUJKREFLQmdncWhrak9QUVFEQXpCeE1Rc3dDUVlEVlFRR0V3SkNSekVUTUJFR0ExVUVDQXdLVTI5bWFXRXRaM0poWkRFT01Bd0dBMVVFQnd3RlUyOW1hV0V4RkRBU0JnTlZCQW9NQzBsdWRHVnlibUZzTFVOQk1SRXdEd1lEVlFRTERBaFRiMlowZDJGeVpURVVNQklHQTFVRUF3d0xTVzUwWlhKdVlXd3RRMEV3SGhjTk1qTXdOREF4TVRjME56RTRXaGNOTWpnd016TXhNVGMwTnpFNFdqQ0JoVEVMTUFrR0ExVUVCaE1DUWtjeERqQU1CZ05WQkFnTUJWTnZabWxoTVI4d0hRWURWUVFLREJaSGJHOWlZV3dnUTI5dWMzVnNkR2x1WnlCTWRHUXVNU0V3SHdZRFZRUUREQmhCYkdWcmMyRnVaR0Z5SUVsMllXNXZkaUJIZVc5dWIzWXhJakFnQmdrcWhraUc5dzBCQ1FFV0UzUmhlbnBBWjJ4dlltRnNZMjl1Y3k1amIyMHdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBU1dHaDNnUXV3VmtacVJ2dWtsSDdaZjJsaTErQWV1RERndGtwbTJ0ejBjNU05bUZIZWxGU3hGaENVQURBVDYwVVkrenhHSDBROWpoY2s1NEczVDNjWGdvNEhwTUlIbU1Ba0dBMVVkRXdRQ01BQXdIUVlEVlIwT0JCWUVGR1ZlUHlOVFNRSFVWaXVsdEE2NzZ6ZGNQTFhoTUI4R0ExVWRJd1FZTUJhQUZBVThiK1pXcUx1MVR4bS9CQUp0M2Jkb3NDT3FNQXNHQTFVZER3UUVBd0lEK0RBN0JnTlZIU1VFTkRBeUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SUdDQ3NHQVFVRkJ3TUVCZ2dyQmdFRkJRY0RBd1lJS3dZQkJRVUhBd2d3VHdZRFZSMFJCRWd3Um9JU2QzZDNMbWRzYjJKaGJHTnZibk11WTI5dGdoQXFMbWRzYjJKaGJHTnZibk11WTI5dGdnbHNiMk5oYkdodmMzU0JFM1JoZW5wQVoyeHZZbUZzWTI5dWN5NWpiMjB3Q2dZSUtvWkl6ajBFQXdNRFp3QXdaQUl3Wi80d00xMWoyMEFsUGVNZFRMV3JIaDFlZDBTak5CanYrQXB1NXg5UjhzSTdUSHVRbHJCaDZxbnc5akc5VC80QUFqQlRpb2V6UjFnOEpoS1N2ankxMzlVNEc5aS9kcnFUUDVpc2RBWDRXN21zSnJkem10aTdUeW8zcjFOOHdJbERXM2s9Il19"",""signature"":""NNUSrE5KECTGM5sKRRpt_c22de6SuM24T31rNpJll1OTnA-sm7ADBTOQA8kJD9UvJIIYse2tlfhEgtj389PaFw""}";

    public static string signedDetached = @"{""protected"":""eyJ0eXAiOiJqb3NlK2pzb24iLCJzaWdUIjoiMjAyMy0wNC0xMVQxMjowOTozNloiLCJzaWdEIjp7Im1JZCI6Imh0dHA6Ly91cmkuZXRzaS5vcmcvMTkxODIvT2JqZWN0SWRCeVVSSUhhc2giLCJwYXJzIjpbImF0dGFjaGVtZW50Il0sImhhc2hNIjoiUzUxMiIsImhhc2hWIjpbIm1mU1YtUXV2N1BUSHNYWUI4aVczVUNTNk9fZThyQVRORlpWWW9PU2pyZ2tEWWdaYUNRcGQ5RTNtbjdvcnRNZ1dkV0I1NF81OWs2Q2RLTDBhZktIUE5RIl0sImN0eXMiOlsidGV4dC9wbGFpbiJdfSwiY3JpdCI6WyJzaWdUIiwic2lnRCJdLCJhbGciOiJFUzI1NiIsImtpZCI6Ik1IRXhDekFKQmdOVkJBWVRBa0pITVJNd0VRWURWUVFJREFwVGIyWnBZUzFuY21Ga01RNHdEQVlEVlFRSERBVlRiMlpwWVRFVU1CSUdBMVVFQ2d3TFNXNTBaWEp1WVd3dFEwRXhFVEFQQmdOVkJBc01DRk52Wm5SM1lYSmxNUlF3RWdZRFZRUUREQXRKYm5SbGNtNWhiQzFEUVE9PSIsIng1dCNTMjU2IjoiTjFhdE1VNHcyUWRubE43YS1JZm9PaVQ2OFV3UHdWMFJ1QmNXcHhuaXdOMCIsIng1YyI6WyJNSUlDN3pDQ0FuYWdBd0lCQWdJQkpEQUtCZ2dxaGtqT1BRUURBekJ4TVFzd0NRWURWUVFHRXdKQ1J6RVRNQkVHQTFVRUNBd0tVMjltYVdFdFozSmhaREVPTUF3R0ExVUVCd3dGVTI5bWFXRXhGREFTQmdOVkJBb01DMGx1ZEdWeWJtRnNMVU5CTVJFd0R3WURWUVFMREFoVGIyWjBkMkZ5WlRFVU1CSUdBMVVFQXd3TFNXNTBaWEp1WVd3dFEwRXdIaGNOTWpNd05EQXhNVGMwTnpFNFdoY05Namd3TXpNeE1UYzBOekU0V2pDQmhURUxNQWtHQTFVRUJoTUNRa2N4RGpBTUJnTlZCQWdNQlZOdlptbGhNUjh3SFFZRFZRUUtEQlpIYkc5aVlXd2dRMjl1YzNWc2RHbHVaeUJNZEdRdU1TRXdId1lEVlFRRERCaEJiR1ZyYzJGdVpHRnlJRWwyWVc1dmRpQkhlVzl1YjNZeElqQWdCZ2txaGtpRzl3MEJDUUVXRTNSaGVucEFaMnh2WW1Gc1kyOXVjeTVqYjIwd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFTV0doM2dRdXdWa1pxUnZ1a2xIN1pmMmxpMStBZXVERGd0a3BtMnR6MGM1TTltRkhlbEZTeEZoQ1VBREFUNjBVWSt6eEdIMFE5amhjazU0RzNUM2NYZ280SHBNSUhtTUFrR0ExVWRFd1FDTUFBd0hRWURWUjBPQkJZRUZHVmVQeU5UU1FIVVZpdWx0QTY3NnpkY1BMWGhNQjhHQTFVZEl3UVlNQmFBRkFVOGIrWldxTHUxVHhtL0JBSnQzYmRvc0NPcU1Bc0dBMVVkRHdRRUF3SUQrREE3QmdOVkhTVUVOREF5QmdnckJnRUZCUWNEQVFZSUt3WUJCUVVIQXdJR0NDc0dBUVVGQndNRUJnZ3JCZ0VGQlFjREF3WUlLd1lCQlFVSEF3Z3dUd1lEVlIwUkJFZ3dSb0lTZDNkM0xtZHNiMkpoYkdOdmJuTXVZMjl0Z2hBcUxtZHNiMkpoYkdOdmJuTXVZMjl0Z2dsc2IyTmhiR2h2YzNTQkUzUmhlbnBBWjJ4dlltRnNZMjl1Y3k1amIyMHdDZ1lJS29aSXpqMEVBd01EWndBd1pBSXdaLzR3TTExajIwQWxQZU1kVExXckhoMWVkMFNqTkJqditBcHU1eDlSOHNJN1RIdVFsckJoNnFudzlqRzlULzRBQWpCVGlvZXpSMWc4SmhLU3ZqeTEzOVU0RzlpL2RycVRQNWlzZEFYNFc3bXNKcmR6bXRpN1R5bzNyMU44d0lsRFczaz0iXX0"",""signature"":""0-R5Dr0wpzHXH8aVwS0FuZLNUvoXais7Taa7TsSfO0WdNiaa2b4k8Q1TU0uaBd0JjsTg6N4BX0oWhKyuoqbykQ""}";

    private X509Certificate2? cert;

    public EcdsaSignVerify()
    {
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
            ETSISigner signer = new ETSISigner(ecKey);

            // Sign payload
            signer.AttachSignersCertificate(cert!);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");
            _ = signer.Encode(JWS.JWSEncodeTypeEnum.Flattened);
        } else {
            throw new Exception("NO ECDSA certificate available");
        }
    }

    [Benchmark]
    public void VerifyETSI_Enveloped()
    {
        // Create signer 
        ETSISigner signer = new ETSISigner();

        // Verify signature
        _ = signer.Verify(signedEnveloped, out byte[] _, out JWS.ETSI.ETSIContextInfo cInfo)
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
                ETSISigner signer = new ETSISigner(ecKey);

                // Sign payload
                signer.AttachSignersCertificate(cert!);
                signer.SignDetached(ms);
                _ = signer.Encode(JWS.JWSEncodeTypeEnum.Flattened);
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
            ETSISigner signer = new ETSISigner();

            // Verify signature
            _ = signer.VerifyDetached(msCheck, signedDetached, out byte[] _, out JWS.ETSI.ETSIContextInfo cInfo)
                    && (cInfo.IsSigningTimeInValidityPeriod.HasValue && cInfo.IsSigningTimeInValidityPeriod.Value)
                    && (cInfo.IsSigningCertDigestValid.HasValue && cInfo.IsSigningCertDigestValid.Value);
        }
    }

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
