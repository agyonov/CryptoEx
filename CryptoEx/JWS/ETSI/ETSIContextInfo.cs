﻿using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.JWS.ETSI;
/// <summary>
/// Some context information for ETSI JWS signatures - certificate, signing time, certificate digest, etc.
/// </summary>
public class ETSIContextInfo : IDisposable
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
    /// Additional certificates
    /// </summary>
    public X509Certificate2Collection? x509Certificate2s { get; set; }
    
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

    /// <summary>
    /// Check the certificate chain, with some standart chain policy
    /// If you need more complex chain policy, you can build your custom
    /// logic suiting data in this class
    /// </summary>
    public bool? IsSigningCertificateValid
    {
        get {
            // Check
            if (SigningCertificate == null) {
                return null;
            }

            // Validate cetificate on chain
            using (var chain = new X509Chain()) {
                // Set some standart chain policy
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
                chain.ChainPolicy.DisableCertificateDownloads = true;
                chain.ChainPolicy.VerificationTimeIgnored = false;
                chain.ChainPolicy.VerificationTime = SigningDateTime.HasValue ? SigningDateTime.Value.ToLocalTime().DateTime : DateTime.Now;

                // Check if we have more certificates
                if (x509Certificate2s != null && x509Certificate2s.Count > 0) {
                    // Add them to the chain
                    foreach (var c in x509Certificate2s) {
                        chain.ChainPolicy.ExtraStore.Add(c);
                    }
                }

                bool res = chain.Build(SigningCertificate);

                for (int i = 0; i < chain.ChainElements.Count; i++) {
                    chain.ChainElements[i].Certificate.Dispose();
                }

                return res;
            }
        }
    }

    /// <summary>
    /// Clear
    /// </summary>
    public void Dispose()
    {
        // Check and free
        if (SigningCertificate != null) {
            SigningCertificate.Dispose();
        }

        // Check and free
        if (x509Certificate2s != null) {
            foreach (var c in x509Certificate2s) {
                c.Dispose();
            }
            x509Certificate2s.Clear();
        }
    }
}
