using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.JWS.ETSI;
/// <summary>
/// Some context information for ETSI JWS signatures - certificate, signing time, certificate digest, etc.
/// </summary>
public class ETSIContextInfo
{
    /// <summary>
    /// The payload content type
    /// </summary>
    public string? PayloadContentType { get; set; } = null;
    /// <summary>
    /// The signing certificate
    /// </summary>
    public X509Certificate2? SigningCertificate { get; set; } = null;
    /// <summary>
    /// The time when the signature was created as UTC - if availabl
    /// </summary>
    public DateTimeOffset? SigningDateTime { get; set; } = null;
    /// <summary>
    /// Digest value of the signing certificate
    /// </summary>
    public byte[]? SigningCertificateDigestValue { get; set; } = null;
    /// <summary>
    /// Digest method of the signing certificate
    /// </summary>
    public HashAlgorithmName? SigningCertificateDagestMethod { get; set; } = null;

    /// <summary>
    /// Check if the signing certificate digest is valid
    /// </summary>
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
            return calcedDigest.SequenceEqual(SigningCertificateDigestValue);
        }
    }

    /// <summary>
    /// Check if the signing time is inside the validity period of the signing certificate
    /// </summary>
    public bool? IsSigningTimeInValidityPeriod
    {
        get {
            // Check
            if (SigningCertificate == null || SigningDateTime == null) {
                return null;
            }

            // Check if time of signing is inside certificate validity period
            if (SigningDateTime > SigningCertificate.NotAfter.ToUniversalTime()) {
                return false;
            }
            if (SigningDateTime < SigningCertificate.NotBefore.ToUniversalTime()) {
                return false;
            }

            return true;
        }
    }
}
