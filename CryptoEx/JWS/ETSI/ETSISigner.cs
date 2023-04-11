using CryptoEx.Utils;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO.Pipes;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;

namespace CryptoEx.JWS.ETSI;
public class ETSISigner : JWSSigner
{
    // hashed data - used in detached mode
    protected byte[]? hashedData = null;
    protected string? mimeTypePayload = null;

    /// <summary>
    /// A constructor without a private key, used for verification
    /// </summary>
    public ETSISigner() : base()
    {
    }

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public ETSISigner(AsymmetricAlgorithm signer) : base(signer)
    {
    }

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing and hash algorithm
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <param name="hashAlgorithm">Hash algorithm, mainly for RSA</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public ETSISigner(AsymmetricAlgorithm signer, HashAlgorithmName hashAlgorithm) : base(signer, hashAlgorithm)
    {
    }

    /// <summary>
    /// Clear some data.
    /// Every thing except the signer and the HashAlgorithmName!
    /// After calling 'Decode' and before calling 'Sign' you MUST call this method! 'Veryfy...' calls this method internally.
    /// </summary>
    public override void Clear()
    {
        // Clear hashed data
        hashedData = null;
        mimeTypePayload = null;

        // call parent
        base.Clear();
    }

    /// <summary>
    /// Add timestamping
    /// </summary>
    /// <param name="funcAsync">Async function that calls Timestamping server, with input data and returns 
    /// response from the server
    /// </param>
    public async Task AddTimestampAsync(Func<byte[], CancellationToken, Task<byte[]>> funcAsync, CancellationToken ct = default)
    {
        byte[] prepSign = Encoding.ASCII.GetBytes(Base64UrlEncoder.Encode(_signatures.FirstOrDefault() ?? Array.Empty<byte>()));
        byte[] tStamp = await funcAsync(prepSign, ct);

        // If canceled
        if (ct.IsCancellationRequested) {
            return;
        }

        // Create the timestamp
        ETSISignatureTimestamp theTimeStamp = new ETSISignatureTimestamp
        {
            SigTst = new ETSITimestampContainer
            {
                TstTokens = new ETSITimestampToken[] {
                         new ETSITimestampToken {
                          Val = Convert.ToBase64String(tStamp)
                         }
                      }
            }
        };

        // Construct unprotected header
        _unprotectedHeader = new ETSIUnprotectedHeader
        {
            EtsiU = new string[] { Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(theTimeStamp, JWSConstants.jsonOptions))) }
        };
    }

    /// <summary>
    /// Digitally sign the attachement, optional payload and protected header in detached mode
    /// </summary>
    /// <param name="attachement">The attached data (file) </param>
    /// <param name="optionalPayload">The optional payload. SHOUD BE JSON STRING.</param>
    /// <param name="mimeTypeAttachement">Optionally mimeType. Defaults to "octet-stream"</param>
    /// <param name="mimeType">Optionally mimeType of the payload</param>
    public virtual void SignDetached(Stream attachement, string? optionalPayload = null, string mimeTypeAttachement = "octet-stream", string? mimeType = null)
    {
        // Hash attachemnt
        using (HashAlgorithm hAlg = SHA512.Create())
        using (AnonymousPipeServerStream apss = new(PipeDirection.In))
        using (AnonymousPipeClientStream apcs = new(PipeDirection.Out, apss.GetClientHandleAsString())) {
            _ = Task.Run(() =>
            {
                try {
                    // Encode
                    Base64UrlEncoder.Encode(attachement, apcs);
                } finally {
                    // Close the pipe
                    apcs.Close(); // To avoid blocking of the pipe.
                }
            });
            hashedData = hAlg.ComputeHash(apss); // Read from the pipe. Blocks until the pipe is closed (Upper Task ends).
        }

        // Prepare header
        mimeTypePayload = mimeType;
        PrepareHeader(mimeTypeAttachement);

        // Form JOSE protected data 
        if (optionalPayload != null) {
            _payload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(optionalPayload));
        }
        _protecteds.Add(_header);
        string calc = optionalPayload == null ? $"{_header}." : $"{_header}.{_payload}";
        if (_signer is RSA) {
            _signatures.Add(((RSA)_signer).SignData(Encoding.ASCII.GetBytes(calc), _algorithmName, RSASignaturePadding.Pkcs1));
        } else if (_signer is ECDsa) {
            _signatures.Add(((ECDsa)_signer).SignData(Encoding.ASCII.GetBytes(calc), _algorithmName));
        }
    }

    /// <summary>
    /// Validates crytical header values, for an ETSI signature
    /// </summary>
    /// <param name="header">The header</param>
    /// <returns>True - present and understood. Flase - other case</returns>
    public static bool ETSIResolutor(ETSIHeader header)
    {
        // No header crit
        if (header.Crit == null) {
            return false;
        }

        // Cycle through crit
        for (int loop = 0; loop < header.Crit.Length; loop++) {
            switch (header.Crit[loop]) {
                case "sigT":
                    // Check
                    if (!DateTimeOffset.TryParseExact(header.SigT, "yyyy-MM-ddTHH:mm:ssZ", DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None, out DateTimeOffset _)) {
                        return false;
                    }
                    break;
                case "x5t#o":
                    return false; // TODO: Implement in future
                case "sigX5ts":
                    return false; // TODO: Implement in future
                case "srCms":
                    return false; // TODO: Implement in future
                case "sigPl":
                    return false; // TODO: Implement in future
                case "srAts":
                    return false; // TODO: Implement in future
                case "adoTst":
                    // Chech
                    if (header.AdoTst == null) {
                        // Not provided
                        return false;
                    } // If not null, then it is parsed and processed by a consumer
                    break;
                case "sigPId":
                    return false; // TODO: Implement in future
                case "sigD":
                    // Check
                    if (header.SigD == null) {
                        // Not provided
                        return false;
                    } // If not null, then it is checked in detached verification
                    break;
                default:
                    return false;
            }
        }

        // All good
        return true;
    }

    /// <summary>
    /// Verify the signature of an enveloped JWS
    /// </summary>
    /// <param name="signature">The JWS signature</param>
    /// <param name="payload">The payload in the signature document</param>
    /// <param name="cInfo">returns the context info about the signature</param>
    /// <returns>True signature is valid. False - no it is invalid</returns>
    /// <exception cref="NotSupportedException">Some more advanced ETSI detached signatures, that are not yet implemented</exception>
    public virtual bool Verify(ReadOnlySpan<char> signature, out byte[] payload, out ETSIContextInfo cInfo)
    {
        // locals
        cInfo = new ETSIContextInfo();

        // Decode
        ReadOnlyCollection<ETSIHeader> eTSIHeaders = Decode<ETSIHeader>(signature, out payload);

        // Fill context info from the first header
        if (eTSIHeaders.Count > 0) {
            // Get the first header
            ETSIHeader eTSIHeader = eTSIHeaders[0];
            // Extract the context info
            ExtractETSIContextInfo(eTSIHeader, cInfo);
        }

        // Try to extract the public keys
        List<AsymmetricAlgorithm> pubKeys = new List<AsymmetricAlgorithm>();
        for (int loop = 0; loop < eTSIHeaders.Count; loop++) {
            // Tre get the public key
            string? x5c = eTSIHeaders[loop].X5c?.FirstOrDefault();
            if (x5c != null) {
                // Get the public key
                try {
                    X509Certificate2 cert = new(Convert.FromBase64String(x5c));
                    RSA? rsa = cert.GetRSAPublicKey();
                    if (rsa != null) {
                        pubKeys.Add(rsa);
                        continue;
                    }
                    ECDsa? ecdsa = cert.GetECDsaPublicKey();
                    if (ecdsa != null) {
                        pubKeys.Add(ecdsa);
                    }
                } catch { }
            }
        }

        // Verify
        try {
            return Verify<ETSIHeader>(pubKeys, ETSIResolutor);
        } finally { Clear(); }
    }

    /// <summary>
    /// Verify the detached signature
    /// </summary>
    /// <param name="attachement">The dettached file</param>
    /// <param name="signature">The JWS signature</param>
    /// <param name="payload">Public keys to use for verification. MUST correspond to each of the JWS headers in the JWS, returned by te Decode method!</param>
    /// <param name="cInfo">Etsi headers returnd by Decode method</param>
    /// <returns>True / false = valid / invalid signature check</returns>
    /// <exception cref="NotSupportedException">Some more advanced ETSI detached signatures, that are not yet implemented</exception>
    public virtual bool VerifyDetached(Stream attachement, ReadOnlySpan<char> signature, out byte[] payload, out ETSIContextInfo cInfo)
    {
        // locals
        cInfo = new ETSIContextInfo();

        // Decode
        ReadOnlyCollection<ETSIHeader> eTSIHeaders = Decode<ETSIHeader>(signature, out payload);

        // Fill context info from the first header
        if (eTSIHeaders.Count > 0) {
            // Get the first header
            ETSIHeader eTSIHeader = eTSIHeaders[0];
            // Extract the context info
            ExtractETSIContextInfo(eTSIHeader, cInfo);
        }

        // Try to extract the public keys
        List<AsymmetricAlgorithm> pubKeys = new List<AsymmetricAlgorithm>();
        for (int loop = 0; loop < eTSIHeaders.Count; loop++) {
            // Tre get the public key
            string? x5c = eTSIHeaders[loop].X5c?.FirstOrDefault();
            if (x5c != null) {
                // Get the public key
                try {
                    X509Certificate2 cert = new(Convert.FromBase64String(x5c));
                    RSA? rsa = cert.GetRSAPublicKey();
                    if (rsa != null) {
                        pubKeys.Add(rsa);
                        continue;
                    }
                    ECDsa? ecdsa = cert.GetECDsaPublicKey();
                    if (ecdsa != null) {
                        pubKeys.Add(ecdsa);
                    }
                } catch { }
            }
        }

        // Verify
        try {
            return VerifyDetached(attachement, pubKeys, eTSIHeaders);
        } finally { Clear(); }
    }

    // Verify detached ETSI signature
    protected virtual bool VerifyDetached(Stream attachement, IReadOnlyList<AsymmetricAlgorithm> publicKeys, ReadOnlyCollection<ETSIHeader> etsiHeaders)
    {
        if (etsiHeaders.Count != publicKeys.Count) {
            return false;
        }

        // Call general verify
        bool res = base.Verify<ETSIHeader>(publicKeys, ETSIResolutor);

        // Check
        if (res != true) {
            return res;
        }

        // for each public key - verify attachement
        for (int loop = 0; loop < publicKeys.Count; loop++) {
            // get header
            ETSIHeader header = etsiHeaders[loop];

            // Check. This method allows just one signed attachement. ETSI generally allows more.
            // Someone can implement it in future - New method with first parameter as array of streams
            if (header.SigD == null || header.SigD.Pars.Length != 1 || header.SigD.HashV == null || header.SigD.HashV.Length != 1) {
                return false;
            }
            if (header.SigD.MId != ETSIConstants.ETSI_DETACHED_PARTS_OBJECT_HASH) {
                throw new NotSupportedException($"For now only {ETSIConstants.ETSI_DETACHED_PARTS_OBJECT_HASH} is supported.");
            }

            // Hash attachemnt
            byte[] lHashedData;
            using (HashAlgorithm hAlg = header.SigD.HashM switch
            {
                ETSIConstants.SHA512 => SHA512.Create(),
                ETSIConstants.SHA384 => SHA384.Create(),
                ETSIConstants.SHA256 => SHA256.Create(),
                _ => throw new NotSupportedException($"Hash algorithm {header.SigD.HashM} is not supported.")
            })
            using (AnonymousPipeServerStream apss = new(PipeDirection.In))
            using (AnonymousPipeClientStream apcs = new(PipeDirection.Out, apss.GetClientHandleAsString())) {
                _ = Task.Run(() =>
                {
                    try {
                        // Encode
                        Base64UrlEncoder.Encode(attachement, apcs);
                    } finally {
                        // Close the pipe
                        apcs.Close(); // To avoid blocking of the pipe.
                    }
                });
                lHashedData = hAlg.ComputeHash(apss); // Read from the pipe. Blocks until the pipe is closed (Upper Task ends).
            }

            // Get sent data
            byte[] sentHash = Base64UrlEncoder.Decode(header.SigD.HashV[0]);

            // Compare
            if (!sentHash.SequenceEqual(lHashedData)) {
                return false;
            }
        }

        // return 
        return res;
    }

    // Extract the context info from the ETSI header
    protected virtual void ExtractETSIContextInfo(ETSIHeader eTSIHeader, ETSIContextInfo cInfo)
    {
        // Try to extract the signing time
        if (DateTimeOffset.TryParseExact(eTSIHeader.SigT, "yyyy-MM-ddTHH:mm:ssZ", DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None, out DateTimeOffset dto)) {
            cInfo.SigningDateTime = dto;
        }
        // Try to extract the signing certificate
        if (eTSIHeader.X5c != null && eTSIHeader.X5c.Length > 0) {
            try {
                cInfo.SigningCertificate = new X509Certificate2(Convert.FromBase64String(eTSIHeader.X5c[0]));
            } catch { }
        }
        // Try to extract the signing certificate digest
        if (!string.IsNullOrEmpty(eTSIHeader.X5)) {
            cInfo.SigningCertificateDigestValue = Base64UrlEncoder.Decode(eTSIHeader.X5);
            cInfo.SigningCertificateDagestMethod = HashAlgorithmName.SHA256;
        }
        // Try to set content info
        cInfo.PayloadContentType = eTSIHeader.Cty;
    }

    // Prepare header values
    protected override void PrepareHeader(string? mimeType = null)
    {
        // check
        if (_certificate == null) {
            throw new ArgumentNullException(nameof(_certificate));
        }

        if (string.IsNullOrEmpty(_algorithmNameJws)) {
            throw new ArgumentNullException(nameof(_algorithmNameJws));
        }

        // header ETSI
        ETSIHeader etsHeader;
        _header = string.Empty;

        // Attached
        if (hashedData == null) {
            // Prepare header
            etsHeader = new ETSIHeader
            {
                Alg = _algorithmNameJws,
                Cty = mimeType,
                Kid = Convert.ToBase64String(_certificate.IssuerName.RawData),
                SigT = $"{DateTimeOffset.UtcNow:yyyy-MM-ddTHH:mm:ssZ}",
                X5 = Base64UrlEncoder.Encode(_certificate.GetCertHash(HashAlgorithmName.SHA256)),
                X5c = new string[] { Convert.ToBase64String(_certificate.RawData) }
            };
        } else {
            // Prepare header
            if (_additionalCertificates == null || _additionalCertificates.Count < 1) {
                etsHeader = new ETSIHeader
                {
                    Alg = _algorithmNameJws,
                    Cty = mimeTypePayload,
                    Kid = Convert.ToBase64String(_certificate.IssuerName.RawData),
                    SigT = $"{DateTimeOffset.UtcNow:yyyy-MM-ddTHH:mm:ssZ}",
                    X5 = Base64UrlEncoder.Encode(_certificate.GetCertHash(HashAlgorithmName.SHA256)),
                    X5c = new string[] { Convert.ToBase64String(_certificate.RawData) },
                    SigD = new ETSIDetachedParts
                    {
                        Pars = new string[] { "attachement" },
                        HashM = ETSIConstants.SHA512,
                        HashV = new string[]
                        {
                            Base64UrlEncoder.Encode(hashedData)
                        },
                        Ctys = new string[] { mimeType ?? "octed-stream" }
                    }
                };
            } else {
                string[] strX5c = new string[_additionalCertificates.Count + 1];
                strX5c[0] = Convert.ToBase64String(_certificate.RawData);
                for (int loop = 0; loop < _additionalCertificates.Count; loop++) {
                    strX5c[loop + 1] = Convert.ToBase64String(_additionalCertificates[loop].RawData);
                }
                etsHeader = new ETSIHeader
                {
                    Alg = _algorithmNameJws,
                    Cty = mimeTypePayload,
                    Kid = Convert.ToBase64String(_certificate.IssuerName.RawData),
                    SigT = $"{DateTimeOffset.UtcNow:yyyy-MM-ddTHH:mm:ssZ}",
                    X5 = Base64UrlEncoder.Encode(_certificate.GetCertHash(HashAlgorithmName.SHA256)),
                    X5c = strX5c,
                    SigD = new ETSIDetachedParts
                    {
                        Pars = new string[] { "attachement" },
                        HashM = ETSIConstants.SHA512,
                        HashV = new string[]
                        {
                            Base64UrlEncoder.Encode(hashedData)
                        },
                        Ctys = new string[] { mimeType ?? "octed-stream" }
                    }
                };
            }
        }

        // Serialize header
        using (MemoryStream ms = new(8192)) {
            JsonSerializer.Serialize(ms, etsHeader, JWSConstants.jsonOptions);
            _header = Base64UrlEncoder.Encode(ms.ToArray());
        }
    }
}
