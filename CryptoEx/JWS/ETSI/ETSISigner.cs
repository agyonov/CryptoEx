using CryptoEx.Utils;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace CryptoEx.JWS.ETSI;
public class ETSISigner : JWSSigner
{
    // hashed data - used in detached mode
    private byte[]? hashedData = null;
    private string? mimeTypePayload = null;

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
    /// <param name="useRSAPSS">In case of RSA, whether to use RSA-PSS</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public ETSISigner(AsymmetricAlgorithm signer, HashAlgorithmName hashAlgorithm, bool useRSAPSS = false) : base(signer, hashAlgorithm, useRSAPSS)
    {
    }

    /// <summary>
    /// A constructiror with an private key - HMAC, used for signing.
    /// I doubt that for ETSI you can use HMAC, but still here is it
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public ETSISigner(HMAC signer) : base(signer)
    {
        throw new Exception("As of ETSI TS 119 312 V1.3.1, p. 6.2.2 HMAC is not supported");
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
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The type 'ETSISignatureTimestamp' is source generated and attached to JSONOptions")]
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
                TstTokens = [
                         new ETSITimestampToken {
                          Val = Convert.ToBase64String(tStamp)
                         }
                      ]
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
    /// <param name="typHeaderparameter">Optionally the 'typ' header parameter https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9,
    /// to put in the header.
    /// </param>
    /// <param name="b64">Wheter to use an Unencoded Payload Option - https://www.rfc-editor.org/rfc/rfc7797.
    /// By defult it is not used, so the payload is encoded. 
    /// If you want to use it, set it to FALSE. And use it carefully and with understanding.
    /// </param>
    public void SignDetached(Stream attachement, string? optionalPayload = null, string mimeTypeAttachement = "octet-stream", string? mimeType = null, string? typHeaderparameter = null, bool? b64 = null)
    {
        // PSS RSA
        bool PSSRSA = false;
        if (_algorithmNameJws != null && _algorithmNameJws.StartsWith("PS")) {
            PSSRSA = true;
        }

        // Once set, it cannot be changed
        if (_b64 == null) {
            _b64 = b64;
        } else {
            if (_b64 != null && (b64 == null || _b64.Value != b64.Value)) {
                throw new Exception("b64 header parameter already set");
            }
        }

        // Hash attachemnt
        if (b64 == null || b64.Value) {
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
        } else {
            using (HashAlgorithm hAlg = SHA512.Create()) {
                /// Hash it
                hashedData = hAlg.ComputeHash(attachement);
            }
        }

        // Prepare header
        mimeTypePayload = mimeType;
        _signatureTypHeaderParameter = typHeaderparameter;
        PrepareHeader(mimeTypeAttachement);

        // Form JOSE protected data 
        if (optionalPayload != null) {
            _payload = _b64 == null || _b64.Value ? Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(optionalPayload)) : optionalPayload;
        }
        _protecteds.Add(_header);
        byte[] calc;
        // If we have a payload, we need to add it to the calc
        if (optionalPayload == null) {
            calc = Encoding.ASCII.GetBytes($"{_header}.");
        } else {
            // No b64
            if (b64 == null || b64.Value) {
                calc = Encoding.ASCII.GetBytes($"{_header}.{_payload}");
            } else {
                // Create sign data buffer
                calc = new byte[_header.Length + Encoding.UTF8.GetByteCount(_payload ?? string.Empty) + 1];

                // Copy header
                Encoding.ASCII.GetBytes($"{_header}.", calc);

                // Copy payload
                Span<byte> slice = new(calc, _header.Length + 1, calc.Length - (_header.Length + 1));
                Encoding.UTF8.GetBytes(_payload ?? string.Empty, slice);
            }
        }

        // Sign
        if (_signer != null) {
            _signatures.Add(cryptoOperations.DoAsymetricSign(_signer, calc, _algorithmName, PSSRSA));
        } else {
            throw new Exception("As of ETSI TS 119 312 V1.3.1, p. 6.2.2 it shall be RSA or ECDSA");
        }
    }

    /// <summary>
    /// Digitally sign the attachement, optional payload and protected header in detached mode
    /// Async version, for when the attachement is a network stream or some other stream that may be
    /// good to be read async.
    /// </summary>
    /// <param name="attachement">The attached data (file) </param>
    /// <param name="optionalPayload">The optional payload. SHOUD BE JSON STRING.</param>
    /// <param name="mimeTypeAttachement">Optionally mimeType. Defaults to "octet-stream"</param>
    /// <param name="mimeType">Optionally mimeType of the payload</param>
    /// <param name="typHeaderparameter">Optionally the 'typ' header parameter https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9,
    /// to put in the header.
    /// </param>
    /// <param name="b64">Wheter to use an Unencoded Payload Option - https://www.rfc-editor.org/rfc/rfc7797.
    /// By defult it is not used, so the payload is encoded. 
    /// If you want to use it, set it to FALSE. And use it carefully and with understanding.
    /// </param>
    public async Task SignDetachedAsync(Stream attachement, string? optionalPayload = null, string mimeTypeAttachement = "octet-stream", string? mimeType = null, string? typHeaderparameter = null, bool? b64 = null)
    {
        // PSS RSA
        bool PSSRSA = false;
        if (_algorithmNameJws != null && _algorithmNameJws.StartsWith("PS")) {
            PSSRSA = true;
        }

        // Once set, it cannot be changed
        if (_b64 == null) {
            _b64 = b64;
        } else {
            if (_b64 != null && (b64 == null || _b64.Value != b64.Value)) {
                throw new Exception("b64 header parameter already set");
            }
        }

        // Hash attachemnt
        if (b64 == null || b64.Value) {
            using (HashAlgorithm hAlg = SHA512.Create())
            using (AnonymousPipeServerStream apss = new(PipeDirection.In))
            using (AnonymousPipeClientStream apcs = new(PipeDirection.Out, apss.GetClientHandleAsString())) {
                _ = Task.Run(async () =>
                {
                    try {
                        // Encode
                        await Base64UrlEncoder.EncodeAsync(attachement, apcs);
                    } finally {
                        // Close the pipe
                        apcs.Close(); // To avoid blocking of the pipe.
                    }
                });
                hashedData = await hAlg.ComputeHashAsync(apss); // Read from the pipe. Blocks until the pipe is closed (Upper Task ends).
            }
        } else {
            using (HashAlgorithm hAlg = SHA512.Create()) {
                /// Hash it
                hashedData = hAlg.ComputeHash(attachement);
            }
        }

        // Prepare header
        mimeTypePayload = mimeType;
        _signatureTypHeaderParameter = typHeaderparameter;
        PrepareHeader(mimeTypeAttachement);

        // Form JOSE protected data 
        if (optionalPayload != null) {
            _payload = _b64 == null || _b64.Value ? Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(optionalPayload)) : optionalPayload;
        }
        _protecteds.Add(_header);
        byte[] calc;
        // If we have a payload, we need to add it to the calc
        if (optionalPayload == null) {
            calc = Encoding.ASCII.GetBytes($"{_header}.");
        } else {
            // No b64
            if (b64 == null || b64.Value) {
                calc = Encoding.ASCII.GetBytes($"{_header}.{_payload}");
            } else {
                // Create sign data buffer
                calc = new byte[_header.Length + Encoding.UTF8.GetByteCount(_payload ?? string.Empty) + 1];

                // Copy header
                Encoding.ASCII.GetBytes($"{_header}.", calc);

                // Copy payload
                Encoding.UTF8.GetBytes(_payload ?? string.Empty, 0, _payload?.Length ?? 0, calc, _header.Length + 1);
            }
        }

        // Sign
        if (_signer != null) {
            _signatures.Add(cryptoOperations.DoAsymetricSign(_signer, calc, _algorithmName, PSSRSA));
        } else {
            throw new Exception("As of ETSI TS 119 312 V1.3.1, p. 6.2.2 it shall be RSA or ECDSA");
        }
    }

    /// <summary>
    /// Verify the signature of an enveloped JWS
    /// </summary>
    /// <param name="signature">The JWS signature</param>
    /// <param name="payload">The payload in the signature document</param>
    /// <param name="cInfo">returns the context info about the signature</param>
    /// <returns>True signature is valid. False - no it is invalid</returns>
    /// <exception cref="NotSupportedException">Some more advanced ETSI detached signatures, that are not yet implemented</exception>
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The type 'ETSIHeader' is source generated and attached to JSONOptions")]
    public bool Verify(ReadOnlySpan<char> signature, out byte[] payload, out ETSIContextInfo cInfo)
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
            AsymmetricAlgorithm? pubKey = GetPublicKeyFromCertificate(x5c);
            if (pubKey != null) {
                pubKeys.Add(pubKey);
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
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The type 'ETSIHeader' is source generated and attached to JSONOptions")]
    public bool VerifyDetached(Stream attachement, ReadOnlySpan<char> signature, out byte[] payload, out ETSIContextInfo cInfo)
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
            AsymmetricAlgorithm? pubKey = GetPublicKeyFromCertificate(x5c);
            if (pubKey != null) {
                pubKeys.Add(pubKey);
            }
        }

        // Verify
        try {
            return VerifyDetached(attachement, pubKeys, eTSIHeaders);
        } finally { Clear(); }
    }

    /// <summary>
    /// Verify the detached signature.
    /// Async version, for when the attachement is a network stream or some other stream that may be
    /// good to be read async.
    /// 
    /// NB. Unfortunatelly Async methods can not have out parameters, so the payload and cInfo, are not provided
    /// out of the box. They are however available if you call the Decode method. So ypu can call Decode, 
    /// after successfull check of the signature, by this method, to get the payload and cInfo.
    /// </summary>
    /// <param name="attachement">The dettached file</param>
    /// <param name="signature">The JWS signature</param>
    /// <param name="payload">Public keys to use for verification. MUST correspond to each of the JWS headers in the JWS, returned by te Decode method!</param>
    /// <param name="cInfo">Etsi headers returnd by Decode method</param>
    /// <returns>True / false = valid / invalid signature check</returns>
    /// <exception cref="NotSupportedException">Some more advanced ETSI detached signatures, that are not yet implemented</exception>
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The type 'ETSIHeader' is source generated and attached to JSONOptions")]
    public async Task<bool> VerifyDetachedAsync(Stream attachement, string signature)
    {
        // Decode
        ReadOnlyCollection<ETSIHeader> eTSIHeaders = Decode<ETSIHeader>(signature, out byte[] _);

        // Try to extract the public keys
        List<AsymmetricAlgorithm> pubKeys = new List<AsymmetricAlgorithm>();
        for (int loop = 0; loop < eTSIHeaders.Count; loop++) {
            // Tre get the public key
            string? x5c = eTSIHeaders[loop].X5c?.FirstOrDefault();
            AsymmetricAlgorithm? pubKey = GetPublicKeyFromCertificate(x5c);
            if (pubKey != null) {
                pubKeys.Add(pubKey);
            }
        }

        // Verify
        try {
            return await VerifyDetachedAsync(attachement, pubKeys, eTSIHeaders);
        } finally { Clear(); }
    }

    /// <summary>
    /// Extract only the ETSI context info and payload, from the signature.
    /// To be used mainly with VerifyAsync
    /// </summary>
    /// <param name="signature">The signature</param>
    /// <param name="payload">The payload</param>
    /// <returns>The ETSI context info</returns>
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The type 'ETSIHeader' is source generated and attached to JSONOptions")]
    public ETSIContextInfo ExtractContextInfo(string signature, out byte[] payload)
    {
        // locals
        ETSIContextInfo res = new ETSIContextInfo();

        // Decode
        ReadOnlyCollection<ETSIHeader> eTSIHeaders = Decode<ETSIHeader>(signature, out payload);

        // Check
        if (eTSIHeaders.Count > 0) {
            // Convert
            ExtractETSIContextInfo(eTSIHeaders[0], res);
        }

        // Return   
        return res;
    }

    // Prepare header values
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The type 'ETSIHeader' is source generated and attached to JSONOptions")]
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

        // Prepare general header
        etsHeader = new ETSIHeader
        {
            Alg = _algorithmNameJws,
            Jku = _keyUrl,
            Jwk = _key,
            Kid = Convert.ToBase64String(_certificate.IssuerName.RawData),
            SigT = $"{DateTimeOffset.UtcNow:yyyy-MM-ddTHH:mm:ssZ}",
            X5 = Base64UrlEncoder.Encode(_certificate.GetCertHash(HashAlgorithmName.SHA256)),
            X5u = _certificateUrl,
            Typ = _signatureTypHeaderParameter,
            Cty = mimeType,
            Crit = new string[] { "sigT" }
        };

        // Prepare header - add signing certificate(s)
        if (_additionalCertificates == null || _additionalCertificates.Count < 1) {
            etsHeader.X5c = new string[] { Convert.ToBase64String(_certificate.RawData) };
        } else {
            string[] strX5c = new string[_additionalCertificates.Count + 1];
            strX5c[0] = Convert.ToBase64String(_certificate.RawData);
            for (int loop = 0; loop < _additionalCertificates.Count; loop++) {
                strX5c[loop + 1] = Convert.ToBase64String(_additionalCertificates[loop].RawData);
            }
            etsHeader.X5c = strX5c;
        }

        // De-Attached
        if (hashedData != null) {
            // Prepare header - add detached info
            etsHeader.SigD = new ETSIDetachedParts
            {
                Pars = new string[] { "attachement" },
                HashM = ETSIConstants.SHA512,
                HashV = new string[]
                       {
                            Base64UrlEncoder.Encode(hashedData)
                       },
                Ctys = new string[] { mimeType ?? "octed-stream" }
            };

            // Add 
            if (!etsHeader.Crit.Contains("sigD")) {
                etsHeader.Crit = etsHeader.Crit.Append("sigD").ToArray();
            }
        }

        // Do some logic for b64
        if (_b64 != null) {
            // Set b64 value
            etsHeader.B64 = _b64.Value;
        }

        // Serialize header
        using (MemoryStream ms = new(8192)) {
            JsonSerializer.Serialize(ms, etsHeader, JWSConstants.jsonOptions);
            _header = Base64UrlEncoder.Encode(ms.ToArray());
        }
    }

    /// <summary>
    /// Tryies to retrieve the public key from the certificate
    /// </summary>
    /// <param name="x5c">The certificate</param>
    /// <returns>The public key</returns>
    protected virtual AsymmetricAlgorithm? GetPublicKeyFromCertificate(string? x5c)
    {
        if (x5c != null) {
            // Get the public key
            try {
                X509Certificate2 cert = new(Convert.FromBase64String(x5c));
                RSA? rsa = cert.GetRSAPublicKey();
                if (rsa != null) {
                    return rsa;
                }
                ECDsa? ecdsa = cert.GetECDsaPublicKey();
                if (ecdsa != null) {
                    return ecdsa;
                }
            } catch { }
        }

        // General return
        return null;
    }

    /// <summary>
    /// Validates crytical header values, for an ETSI signature
    /// </summary>
    /// <param name="header">The header</param>
    /// <returns>True - present and understood. Flase - other case</returns>
    private static bool ETSIResolutor(ETSIHeader header)
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
                    } else { // If not null, then it is checked in detached verification
                        // Check values of B64 in case of detached headers
                        if (header.SigD.MId == ETSIConstants.ETSI_DETACHED_PARTS_HTTP_HEADERS) {
                            if (header.B64 == null || header.B64.Value) {
                                // Not allowed
                                return false;
                            }
                        }
                    }
                    break;
                case "b64":
                    // Check
                    if (header.B64 == null) {
                        // Not provided
                        return false;
                    }
                    break;
                default:
                    return false;
            }
        }

        // All good
        return true;
    }

    // Extract the context info from the ETSI header
    private void ExtractETSIContextInfo(ETSIHeader eTSIHeader, ETSIContextInfo cInfo)
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
            if (eTSIHeader.X5c.Length > 1) {
                cInfo.x509Certificate2s = new X509Certificate2Collection();
                for (int loop = 1; loop < eTSIHeader.X5c.Length; loop++) {
                    try {
                        cInfo.x509Certificate2s.Add(new X509Certificate2(Convert.FromBase64String(eTSIHeader.X5c[loop])));
                    } catch { }
                }
            }
        }
        // Try to extract the signing certificate digest
        if (!string.IsNullOrEmpty(eTSIHeader.X5)) {
            cInfo.SigningCertificateDigestValue = Base64UrlEncoder.Decode(eTSIHeader.X5);
            cInfo.SigningCertificateDagestMethod = HashAlgorithmName.SHA256;
        }
        // Try to set content info
        cInfo.PayloadContentType = eTSIHeader.Cty;
    }


    // Verify detached ETSI signature
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The type 'ETSIHeader' is source generated and attached to JSONOptions")]
    private bool VerifyDetached(Stream attachement, IReadOnlyList<AsymmetricAlgorithm> publicKeys, ReadOnlyCollection<ETSIHeader> etsiHeaders)
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
            if (header.B64 == null || header.B64.Value) {
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
            } else {
                using (HashAlgorithm hAlg = header.SigD.HashM switch
                {
                    ETSIConstants.SHA512 => SHA512.Create(),
                    ETSIConstants.SHA384 => SHA384.Create(),
                    ETSIConstants.SHA256 => SHA256.Create(),
                    _ => throw new NotSupportedException($"Hash algorithm {header.SigD.HashM} is not supported.")
                }) {
                    // Compute hash
                    lHashedData = hAlg.ComputeHash(attachement);
                }
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

    // Verify detached ETSI signature - aync version
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The type 'ETSIHeader' is source generated and attached to JSONOptions")]
    private async Task<bool> VerifyDetachedAsync(Stream attachement, IReadOnlyList<AsymmetricAlgorithm> publicKeys, ReadOnlyCollection<ETSIHeader> etsiHeaders)
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
            if (header.B64 == null || header.B64.Value) {
                using (HashAlgorithm hAlg = header.SigD.HashM switch
                {
                    ETSIConstants.SHA512 => SHA512.Create(),
                    ETSIConstants.SHA384 => SHA384.Create(),
                    ETSIConstants.SHA256 => SHA256.Create(),
                    _ => throw new NotSupportedException($"Hash algorithm {header.SigD.HashM} is not supported.")
                })
                using (AnonymousPipeServerStream apss = new(PipeDirection.In))
                using (AnonymousPipeClientStream apcs = new(PipeDirection.Out, apss.GetClientHandleAsString())) {
                    _ = Task.Run(async () =>
                    {
                        try {
                            // Encode
                            await Base64UrlEncoder.EncodeAsync(attachement, apcs);
                        } finally {
                            // Close the pipe
                            apcs.Close(); // To avoid blocking of the pipe.
                        }
                    });
                    lHashedData = await hAlg.ComputeHashAsync(apss); // Read from the pipe. Blocks until the pipe is closed (Upper Task ends).
                }
            } else {
                using (HashAlgorithm hAlg = header.SigD.HashM switch
                {
                    ETSIConstants.SHA512 => SHA512.Create(),
                    ETSIConstants.SHA384 => SHA384.Create(),
                    ETSIConstants.SHA256 => SHA256.Create(),
                    _ => throw new NotSupportedException($"Hash algorithm {header.SigD.HashM} is not supported.")
                }) {
                    // Compute hash
                    lHashedData = hAlg.ComputeHash(attachement);
                }
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
}
