using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.XML.ETSI;
public class ETSIContextInfo
{
    public X509Certificate2? SigningCertificate { get; set; } = null;
    public DateTimeOffset? SigningDateTime { get; set; } = null;
    public byte[]? SigningCertificateDigestValue { get; set; } = null;
    public HashAlgorithmName? SigningCertificateDagestMethod { get; set; } = null;

    public bool? IsSigningCertDigestValid
    {
        get {
            // Check
            if (SigningCertificate == null || SigningCertificateDigestValue == null || SigningCertificateDagestMethod == null) {
                return null;
            }

            // Calc digest 
            byte[] calcedDigest = SigningCertificate.GetCertHash(SigningCertificateDagestMethod.Value);

            // Check if equal
            if (calcedDigest.Length != SigningCertificateDigestValue.Length) {
                return false;
            }
            for (int loop = 0; loop < calcedDigest.Length; loop++) {
                if (calcedDigest[loop] != SigningCertificateDigestValue[loop]) {
                    return false;
                }
            }
            return true;
        }
    }
}
