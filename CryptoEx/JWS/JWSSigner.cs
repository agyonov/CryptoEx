﻿using CryptoEx.JWK;
using CryptoEx.Utils;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace CryptoEx.JWS;

/// <summary>
/// General JOSE signer. This class can be used for signing and verification of modes JWS.
/// It can also be easilly extended to support other modes. For example, see ETSI JOSE signer in current project.
/// </summary>
public class JWSSigner
{
    // The signing key
    protected AsymmetricAlgorithm? _signer;
    protected HMAC? _signerHmac;

    // Jws algorithm name
    protected string? _algorithmNameJws;

    // .NET algorithm name
    protected HashAlgorithmName _algorithmName;

    // Possibly the certificate
    protected X509Certificate2? _certificate;

    // Possibly the certificate url
    protected string? _certificateUrl;

    // Possibly the key id
    protected string? _keyId;

    // Possibly the key url
    protected string? _keyUrl;

    // Possibly the key
    protected Jwk? _key;

    // pssibly additional certificates 
    protected IReadOnlyList<X509Certificate2>? _additionalCertificates;

    // Some header 
    protected string _header;

    // Some unprotected header 
    protected object? _unprotectedHeader = null;

    // JOSE protected data
    protected readonly List<string> _protecteds;

    // JOSE payload
    protected string? _payload = null;

    // The calculate signature
    protected readonly List<byte[]> _signatures;

    // The 'typ' header parameter as of https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9
    protected string? _signatureTypHeaderParameter;

    // The 'b64' header parameter as of https://www.rfc-editor.org/rfc/rfc7797
    protected bool? _b64 = null;

    // Internal class signer
    protected CryptoOperations cryptoOperations;

    /// <summary>
    /// A constructor without a private key, used for verification
    /// </summary>
    public JWSSigner()
    {
        // Store
        _signatures = new List<byte[]>();
        _protecteds = new List<string>();
        _header = string.Empty;
        cryptoOperations = new CryptoOperations();
    }

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public JWSSigner(AsymmetricAlgorithm signer) : this()
    {
        // Store
        SetNewSigningKey(signer, null, false);
    }

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing and hash algorithm
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <param name="hashAlgorithm">Hash algorithm, mainly for RSA</param>
    /// <param name="useRSAPSS">In case of RSA, whether to use RSA-PSS</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public JWSSigner(AsymmetricAlgorithm signer, HashAlgorithmName hashAlgorithm, bool useRSAPSS = false) : this()
    {
        // Store
        SetNewSigningKey(signer, hashAlgorithm, useRSAPSS);
    }

    /// <summary>
    /// A constructiror with an private key - HMAC, used for signing
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public JWSSigner(HMAC signer) : this()
    {
        // Store
        SetNewSigningKey(signer);
    }

    /// <summary>
    /// Clear some data.
    /// Every thing except the signer and the HashAlgorithmName!
    /// After calling 'Decode' and before calling 'Sign' next time you MUST call this method! 'Verify...' calls this method internally.
    /// </summary>
    public virtual void Clear()
    {
        _certificate = null;
        _additionalCertificates = null;
        _header = string.Empty;
        _protecteds.Clear();
        _payload = null;
        _signatures.Clear();
        _unprotectedHeader = null;
        _signatureTypHeaderParameter = null;
        _certificateUrl = null;
        _keyId = null;
        _keyUrl = null;
        _key = null;
        _b64 = null;
    }

    /// <summary>
    /// Change the signing key. This is useful for example when you want to sign with a new key.
    /// When you want to add a new signature, you set it with this method and then can use 'Sign' method to actually sign with
    /// the newly stetted key.
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <param name="hashAlgorithm">Hash algorithm, mainly for RSA</param>
    /// <param name="useRSAPSS">In case of RSA, whether to use RSA-PSS</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public void SetNewSigningKey(AsymmetricAlgorithm signer, HashAlgorithmName? hashAlgorithm = null, bool useRSAPSS = false)
    {
        // Store
        _signer = signer;
        _signerHmac = null;

        // call switch operation
        var res = cryptoOperations.SetNewSigningKey(signer, hashAlgorithm, useRSAPSS);
        _algorithmNameJws = res.JwsName;
        _algorithmName = res.DotnetName;
    }

    /// <summary>
    /// Change the signing key. This is useful for example when you want to sign with a new key.
    /// When you want to add a new signature, you set it with this method and then can use 'Sign' method to actually sign with
    /// the newly stetted key.
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public void SetNewSigningKey(HMAC signer)
    {
        // Store
        _signer = null;
        _signerHmac = signer;

        // Determine the algorithm
        switch (_signerHmac) {
            case HMACSHA256 _:
                _algorithmNameJws = JWSConstants.HS256;
                _algorithmName = HashAlgorithmName.SHA256;
                break;
            case HMACSHA384 _:
                _algorithmNameJws = JWSConstants.HS384;
                _algorithmName = HashAlgorithmName.SHA384;
                break;
            case HMACSHA512 _:
                _algorithmNameJws = JWSConstants.HS512;
                _algorithmName = HashAlgorithmName.SHA512;
                break;
            default:
                throw new ArgumentException("Invalid key type");
        }
    }

    /// <summary>
    /// Attach the signer's certificate to the JWS. ONLY public part of the certificate is used.
    /// This is optional and is only used to add the x5c, x5t header
    /// An alternative to this method is to use 'AttachSignersOthersProperties' method.
    /// </summary>
    /// <param name="cert">The certificate</param>
    /// <param name="additionalCertificates">The additional certificates to add to the signature</param>
    public void AttachSignersCertificate(X509Certificate2 cert, IReadOnlyList<X509Certificate2>? additionalCertificates = null)
    {
        _certificate = cert;
        _additionalCertificates = additionalCertificates;
    }

    /// <summary>
    /// Attach the onter signer's properties to the JWS. This is optional and is only used to add the jku, jwk, kid, x5u header.
    /// Can be tought as an alternative to 'AttachSignersCertificate' method.
    /// </summary>
    /// <param name="Jku">Optionally URL to download signer's JWK set</param>
    /// <param name="JwKey">Optionally some JWK key to use for signature verification</param>
    /// <param name="Kid">Optionally Key ID</param>
    /// <param name="X5u">Optionally URL to download signer's certificate.</param>
    public void AttachSignersOthersProperties(string? Jku = null, Jwk? JwKey = null, string? Kid = null, string? X5u = null)
    {
        _certificateUrl = X5u;
        _keyId = Kid;
        _keyUrl = Jku;
        _key = JwKey;
    }

    /// <summary>
    /// Digitally sign the payload and protected header.
    /// You may call this method multiple times to add multiple signatures, BEFORE calling 'Encode'.
    /// If you put multiple signatures, you'd better set a new signing key before calling this method,
    /// by calling method 'SetNewSigningKey'.
    /// </summary>
    /// <param name="payload">The payload</param>
    /// <param name="mimeType">Optionally the mime type of the payload, to put in the header</param>
    /// <param name="typHeaderparameter">Optionally the 'typ' header parameter https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9,
    /// to put in the header.
    /// </param>
    /// <param name="b64">Wheter to use an Unencoded Payload Option - https://www.rfc-editor.org/rfc/rfc7797.
    /// By defult it is not used, so the payload is encoded. 
    /// If you want to use it, set it to FALSE. And use it carefully and with understanding.
    /// </param>
    public void Sign(ReadOnlySpan<byte> payload, string? mimeType = null, string? typHeaderparameter = null, bool? b64 = null)
    {
        // PSS RSA
        bool PSSRSA = false;
        if (_algorithmNameJws != null && _algorithmNameJws.StartsWith("PS")) {
            PSSRSA = true;
        }

        // Set it
        _signatureTypHeaderParameter = typHeaderparameter;
        // Once set, it cannot be changed
        if (_b64 == null) {
            _b64 = b64;
        } else {
            if (_b64 != null && (b64 == null || _b64.Value != b64.Value)) {
                throw new Exception("b64 header parameter already set");
            }
        }

        // Prepare header
        PrepareHeader(mimeType);

        // Form JOSE protected data
        _payload = _b64 == null || _b64.Value ? Base64UrlEncoder.Encode(payload) : Encoding.UTF8.GetString(payload);
        _protecteds.Add(_header);

        // Prepare data to sign
        byte[] data;
        if (_b64 == null || _b64.Value) {
            // Create the data to sign
            data = Encoding.ASCII.GetBytes($"{_header}.{_payload}");
        } else {
            // Create sign data buffer
            data = new byte[_header.Length + payload.Length + 1];

            // Encode header
            Encoding.ASCII.GetBytes($"{_header}.", data);

            // Copy header and payload
            Span<byte> slice = new(data, _header.Length + 1, data.Length - (_header.Length + 1));
            payload.CopyTo(slice);
        }

        // Sign
        if (_signer != null) {
            // Do the sign
            _signatures.Add(cryptoOperations.DoAsymetricSign(_signer, data, _algorithmName, PSSRSA));
        } else if (_signerHmac != null) {
            // HMAC case
            _signatures.Add(_signerHmac.ComputeHash(data));
        } else {
            throw new ArgumentNullException(nameof(_algorithmNameJws));
        }
    }

    /// <summary>
    /// Verify the JWS
    /// </summary>
    /// <typeparam name="T">Must be JWSHeader or descendant from the JWSHeader record. Shall hold data about protected headers of the JWS.
    /// For example, it may be ETSI JWS header, or some other header, which is used in the JWS.
    /// </typeparam>
    /// <param name="keys">Public (RSA, ECDS) keys or Symmetric key (HMAC) to use for verification. MUST correspond to each of the JWS headers in the JWS,
    /// returned by te Decode method!
    /// MUST be descendent type from AsymmetricAlgorithm or HMAC</param>
    /// <param name="resolutor">Resolutor if "Cryt" header parameter if it EXISTS in any of the JWS headers in the JWS, returned by te Decode method!
    /// Please provide DECENT resolutor, as this is a SECURITY issue! You may read https://www.rfc-editor.org/rfc/rfc7515#section-4.1.10 for more information.
    /// You may also have a look at the ETSISigner class in the current project, for an example of a resolutor.
    /// IMPORTANT: If the "Cryt" header parameter is not present in any of the JWS headers in the JWS, returned by te Decode method - the resolutor is NOT called!
    /// So you may provide null as the resolutor, as you do not need it.
    /// </param>
    /// <returns>True / false = valid / invalid signature check</returns>
    /// <exception cref="ArgumentException">Some issues exists with the arguments and/or keys provided to this method</exception>
    [RequiresUnreferencedCode("There is not guarantee that the 'T' class is source generated, so Json.Deserialize may not work")]
    public bool Verify<T>(IReadOnlyList<object> keys, Func<T, bool>? resolutor = null) where T : JWSHeader
    {
        // Declare result
        bool result = true;

        try {
            // Get the headers, from the protected data! Do not accept them from the caller!
            List<T> headers = _protecteds.Select(p => JsonSerializer.Deserialize<T>(Base64UrlEncoder.Decode(p), JWSConstants.jsonOptions))
                                                    .Where(p => p != null)
                                                    .ToList()!;

            // Check the number of signatures
            if (headers.Count != _protecteds.Count || headers.Count != keys.Count) {
                return false;
            }

            // Check the signatures of the JWS
            for (int loop = 0; loop < headers.Count; loop++) {
                // Make sure Crytical header is not present or resolutor is provided
                if (headers[loop].Crit != null) {
                    // No resolutor provided !
                    if (resolutor == null) {
                        throw new ArgumentException($"There are crytical parameters in the header. You MUST provide crytical header resolutor!");
                    } else {
                        // Check the crytical headers, by calling the resolutor
                        if (!resolutor(headers[loop])) {
                            return false;
                        }
                    }
                }

                // Prepare data to verify
                byte[] data;
                if (headers[loop].B64 == null || headers[loop].B64!.Value) {
                    // Standard case
                    data = Encoding.ASCII.GetBytes($"{_protecteds[loop]}.{_payload}");
                } else {
                    // Create sign data buffer
                    data = new byte[_protecteds[loop].Length + Encoding.UTF8.GetByteCount(_payload ?? string.Empty) + 1];

                    // Copy header
                    Encoding.ASCII.GetBytes($"{_protecteds[loop]}.", data);

                    // Copy payload
                    Span<byte> slice = new(data, _protecteds[loop].Length + 1, data.Length - (_protecteds[loop].Length + 1));
                    Encoding.UTF8.GetBytes(_payload ?? string.Empty, slice);
                }

                // Verify
                result &= cryptoOperations.DoVerify(keys[loop], headers[loop], data, _signatures[loop]);
            }

            return result;
        } finally { Clear(); }
    }

    /// <summary>
    /// Encode JWS 
    /// </summary>
    /// <param name="type">Type of JWS encoding. Default is Compact.
    /// NB. If there is more than 1 (one) signature, the result is always FULL!</param>
    /// <returns>The encoded JWS</returns>
    /// <exception cref="ArgumentException">Unknow enoding type</exception>
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The types 'JWSFlattened' and 'JWS' are source generated and attached to JSONOptions")]
    public string Encode(JWSEncodeTypeEnum type = JWSEncodeTypeEnum.Compact)
    {
        // Check it
        if (_signatures.Count > 1) {
            type = JWSEncodeTypeEnum.Full;
        } else {
            // If unencoded header is present, we must use Flattened encoding or Full in case of more than 1 signature
            if (_b64 != null && !_b64.Value && type == JWSEncodeTypeEnum.Compact) {
                type = JWSEncodeTypeEnum.Flattened;
            }
        }

        // Encode it
        return type switch
        {
            JWSEncodeTypeEnum.Compact =>
                $"{_protecteds.FirstOrDefault() ?? string.Empty}.{_payload}.{Base64UrlEncoder.Encode(_signatures.FirstOrDefault() ?? Array.Empty<byte>())}",
            JWSEncodeTypeEnum.Flattened =>
                 JsonSerializer.Serialize(new JWSFlattened
                 {
                     Payload = _payload,
                     Protected = _protecteds.FirstOrDefault() ?? string.Empty,
                     Header = _unprotectedHeader,
                     Signature = Base64UrlEncoder.Encode(_signatures.FirstOrDefault() ?? Array.Empty<byte>())
                 }, JWSConstants.jsonOptions),
            JWSEncodeTypeEnum.Full =>
                JsonSerializer.Serialize(new JWS
                {
                    Payload = _payload,
                    Signatures = _signatures.Select((sigItem, index) =>
                        new JWSSignature
                        {
                            Protected = _protecteds[index],
                            Header = _unprotectedHeader,
                            Signature = Base64UrlEncoder.Encode(sigItem)
                        }).ToArray(),
                }, JWSConstants.jsonOptions),
            _ => throw new ArgumentException("Invalid encoding type")
        };
    }

    /// <summary>
    /// Decode JOSE's JWS
    /// </summary>
    /// <typeparam name="T">Must be descendant from the JWSHeader record. Shall hold data about protected headers of the JWS.
    /// For example, it may be ETSI JWS header, or some other header, which is used in the JWS.
    /// </typeparam>
    /// <param name="signature">The JWS</param>
    /// <param name="payload">The payload in JWS</param>
    /// <returns>A collection of JWS headers. Generally will be one, unless JWS is signed by multiple signer.
    /// If signed by multiple signers will return more then one header - for each signer</returns>
    [RequiresUnreferencedCode("There is not guarantee that the 'T' class is source generated, so Json.Deserialize may not work")]
    public ReadOnlyCollection<T> Decode<T>(ReadOnlySpan<char> signature, out byte[] payload) where T : JWSHeader
    {
        // Clear
        Clear();

        // Trim
        signature = signature.Trim();

        // check to see if we have simple encoded signature
        if (signature[0] != '{') {
            // Decode signature as compact one
            DecodeCompact(signature);
        } else {
            // Decode signature as full one
            DecodeFull(signature);
        }

        // Load headers
        ReadOnlyCollection<T> result = _protecteds.Select(p => JsonSerializer.Deserialize<T>(Base64UrlEncoder.Decode(p), JWSConstants.jsonOptions))
                          .Where(p => p != null)
                          .ToList()
                          .AsReadOnly()!;

        // Load payload
        if (result.Any(h => h.B64 != null && !h.B64.Value)) {
            payload = _payload != null ? Encoding.UTF8.GetBytes(_payload) : Array.Empty<byte>();
        } else {
            payload = _payload != null ? Base64UrlEncoder.Decode(_payload) : Array.Empty<byte>();
        }

        // Return header
        return result;
    }

    /// <summary>
    /// Validates crytical header values, for an B64 signature
    /// </summary>
    /// <param name="header">The header</param>
    /// <returns>True - present and understood. Flase - other case</returns>
    public static bool B64Resolutor(JWSHeader header)
    {
        // No header crit
        if (header.Crit == null) {
            return false;
        }

        // Cycle through crit
        for (int loop = 0; loop < header.Crit.Length; loop++) {
            switch (header.Crit[loop]) {
                case "b64":
                    // Check
                    if (header.B64 == null) {
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

    // Prepare header values
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The type 'JWSHeader' is source generated and attached to JSONOptions")]
    protected virtual void PrepareHeader(string? mimeType = null)
    {
        // Set as empty
        _header = string.Empty;

        // Check
        if (string.IsNullOrEmpty(_algorithmNameJws)) {
            throw new ArgumentNullException(nameof(_algorithmNameJws));
        }

        // Prepare general header
        JWSHeader jWSHeader = new JWSHeader
        {
            Alg = _algorithmNameJws,
            Jku = _keyUrl,
            Jwk = _key,
            Kid = _keyId,
            X5u = _certificateUrl,
            Typ = _signatureTypHeaderParameter,
            Cty = mimeType
        };

        // If we have certificate
        if (_certificate != null) {
            // Set certificate sha256
            jWSHeader.X5 = Base64UrlEncoder.Encode(_certificate.GetCertHash(HashAlgorithmName.SHA256));

            // If we do not have additional certificates
            if (_additionalCertificates == null || _additionalCertificates.Count < 1) {
                // Set just one
                jWSHeader.X5c = new string[] { Convert.ToBase64String(_certificate.RawData) };
            } else {
                // Set all
                string[] strX5c = new string[_additionalCertificates.Count + 1];
                strX5c[0] = Convert.ToBase64String(_certificate.RawData);
                for (int loop = 0; loop < _additionalCertificates.Count; loop++) {
                    strX5c[loop + 1] = Convert.ToBase64String(_additionalCertificates[loop].RawData);
                }
                jWSHeader.X5c = strX5c;
            }
        }

        // Do some logic for b64
        if (_b64 != null) {
            // Set b64 value
            jWSHeader.B64 = _b64.Value;

            // Make b64 is in crit
            if (jWSHeader.Crit == null) {
                // Just set it
                jWSHeader.Crit = new string[] { "b64" };
            } else {
                // Append it, if not exists
                if (!jWSHeader.Crit.Contains("b64")) {
                    jWSHeader.Crit = jWSHeader.Crit.Append("b64").ToArray();
                }
            }
        }

        // Serialize header
        using (MemoryStream ms = new(8192)) {
            JsonSerializer.Serialize(ms, jWSHeader, JWSConstants.jsonOptions);
            _header = Base64UrlEncoder.Encode(ms.ToArray());
        }
    }

    // Decode compact encoded signature
    private void DecodeCompact(ReadOnlySpan<char> signature)
    {
        // Read protected
        int index = signature.IndexOf('.');
        if (index < -1) {
            return;
        } else {
            // Add protected
            _protecteds.Add(signature.Slice(0, index).ToString());
        }

        // Read payload
        if (index + 1 < signature.Length) {
            // Get index of next dot
            signature = signature.Slice(index + 1);
            index = signature.IndexOf('.');
            if (index < -1) {
                return;
            } else {
                // Add protected
                _payload = signature.Slice(0, index).ToString();
            }

            // Get signature
            if (index + 1 < signature.Length) {
                _signatures.Add(Base64UrlEncoder.Decode(signature.Slice(index + 1).ToString()));
            }
        }
    }

    // Decode flattened or full encoded signature
    [UnconditionalSuppressMessage("ReflectionAnalysis", "IL2026",
            Justification = "The types 'JWSFlattened' and 'JWS' are source generated and attached to JSONOptions")]
    private void DecodeFull(ReadOnlySpan<char> signature)
    {
        // Firts check if we have "flattened" encoded signature
        JWSFlattened? resFalttened = JsonSerializer.Deserialize<JWSFlattened>(signature, JWSConstants.jsonOptions);
        if (resFalttened != null) {
            // We have flattened
            if (!string.IsNullOrEmpty(resFalttened.Protected) && !string.IsNullOrEmpty(resFalttened.Signature)) {
                _protecteds.Add(resFalttened.Protected);
                _payload = resFalttened.Payload;
                _unprotectedHeader = resFalttened.Header;
                _signatures.Add(Base64UrlEncoder.Decode(resFalttened.Signature));
                return;
            }
        }

        // Check if we have "full" encoded signature
        JWS? res = JsonSerializer.Deserialize<JWS>(signature, JWSConstants.jsonOptions);
        if (res != null) {
            // We have full
            if (res.Signatures != null && res.Signatures.Length > 0) {
                _payload = res.Payload;
                foreach (JWSSignature sig in res.Signatures) {
                    _protecteds.Add(sig.Protected);
                    _unprotectedHeader = sig.Header;
                    _signatures.Add(Base64UrlEncoder.Decode(sig.Signature));
                }
                return;
            }
        }
    }

    /// <summary>
    /// Do asymetric sign and verify in extensible way
    /// </summary>
    public class CryptoOperations
    {
        /// <summary>
        /// Do asymetric sign
        /// </summary>
        /// <param name="signer">The signer - private key</param>
        /// <param name="data">Data to sign</param>
        /// <param name="hashName">Hash name to use</param>
        /// <param name="PSSRSA">For RSA - to use PSS or not</param>
        /// <returns>The signature</returns>
        public virtual byte[] DoAsymetricSign(AsymmetricAlgorithm signer, byte[] data, HashAlgorithmName hashName, bool PSSRSA = false)
        {
            // Do sign
            return signer switch
            {
                RSA rsa => rsa.SignData(data, hashName, PSSRSA ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1),
                ECDsa ecdsa => ecdsa.SignData(data, hashName),
                _ => throw new ArgumentException("Invalid key type."),
            };
        }

        /// <summary>
        /// Do verify the JWS
        /// </summary>
        /// <typeparam name="T">The type of the Header</typeparam>
        /// <param name="key">The Key</param>
        /// <param name="header">The header value</param>
        /// <param name="data">The data to verify</param>
        /// <param name="signature">The signatures</param>
        /// <returns>True / false if it is valid / invalid</returns>
        public virtual bool DoVerify<T>(object key, T header, byte[] data, byte[] signature) where T : JWSHeader
        {
            // locals
            HashAlgorithmName algorithmName;

            // Try get some key
            AsymmetricAlgorithm? aa = key as AsymmetricAlgorithm;
            if (aa != null) {
                switch (aa) {
                    case RSA rsa:
                        // Get algorithm name
                        algorithmName = header.Alg switch
                        {
                            JWSConstants.RS256 => HashAlgorithmName.SHA256,
                            JWSConstants.RS384 => HashAlgorithmName.SHA384,
                            JWSConstants.RS512 => HashAlgorithmName.SHA512,
                            JWSConstants.PS256 => HashAlgorithmName.SHA256,
                            JWSConstants.PS384 => HashAlgorithmName.SHA384,
                            JWSConstants.PS512 => HashAlgorithmName.SHA512,
                            _ => throw new ArgumentException($"Invalid RSA hash algorithm - {header.Alg}")
                        };

                        // PSS RSA
                        bool PSSRSA = false;
                        if (header.Alg.StartsWith("PS")) {
                            PSSRSA = true;
                        }

                        // Verify
                        return rsa.VerifyData(data, signature, algorithmName, PSSRSA ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                    case ECDsa ecdsa:
                        // Get algorithm name
                        algorithmName = header.Alg switch
                        {
                            JWSConstants.ES256 => HashAlgorithmName.SHA256,
                            JWSConstants.ES384 => HashAlgorithmName.SHA384,
                            JWSConstants.ES512 => HashAlgorithmName.SHA512,
                            _ => throw new ArgumentException($"Invalid ECDSA hash algorithm - {header.Alg}")
                        };

                        // Verify
                        return ecdsa.VerifyData(data, signature, algorithmName);
                    default:
                        throw new ArgumentException("Invalid key type.");
                }
            } else {
                // HMAC case
                HMAC? hmac = key as HMAC;

                // Check
                if (hmac != null) {
                    // Get algorithm name
                    _ = header.Alg switch
                    {
                        JWSConstants.HS256 => HashAlgorithmName.SHA256,
                        JWSConstants.HS384 => HashAlgorithmName.SHA384,
                        JWSConstants.HS512 => HashAlgorithmName.SHA512,
                        _ => throw new ArgumentException($"Invalid HMAC hash algorithm - {header.Alg}")
                    };

                    // Verify
                    return hmac.ComputeHash(data).SequenceEqual(signature);
                } else {
                    throw new ArgumentException("Invalid key type.");
                }
            }
        }

        /// <summary>
        /// Change the signing key. This is useful for example when you want to sign with a new key.
        /// When you want to add a new signature, you set it with this method and then can use 'Sign' method to actually sign with
        /// the newly stetted key.
        /// </summary>
        /// <param name="signer">The private key</param>
        /// <param name="hashAlgorithm">Hash algorithm, mainly for RSA</param>
        /// <param name="useRSAPSS">In case of RSA, whether to use RSA-PSS</param>
        /// <returns>Some naming pairs</returns>
        public virtual KeyTypeAlgorithmResult SetNewSigningKey(AsymmetricAlgorithm signer, HashAlgorithmName? hashAlgorithm = null, bool useRSAPSS = false)
        {
            // locals
            string? algorithmNameJws;
            HashAlgorithmName? algorithmName;

            // Determine the algorithm
            switch (signer) {
                case RSA rsa:
                    algorithmNameJws = rsa.KeySize switch
                    {
                        2048 => useRSAPSS ? JWSConstants.PS256 : JWSConstants.RS256,
                        3072 => useRSAPSS ? JWSConstants.PS384 : JWSConstants.RS384,
                        4096 => useRSAPSS ? JWSConstants.PS384 : JWSConstants.RS512,
                        _ => throw new ArgumentException("Invalid RSA key size")
                    };
                    algorithmName = rsa.KeySize switch
                    {
                        2048 => HashAlgorithmName.SHA256,
                        3072 => HashAlgorithmName.SHA384,
                        4096 => HashAlgorithmName.SHA512,
                        _ => throw new ArgumentException("Invalid RSA key size")
                    };
                    break;
                case ECDsa ecdsa:
                    algorithmNameJws = ecdsa.KeySize switch
                    {
                        256 => JWSConstants.ES256,
                        384 => JWSConstants.ES384,
                        521 => JWSConstants.ES512,
                        _ => throw new ArgumentException("Invalid ECDSA key size")
                    };
                    algorithmName = ecdsa.KeySize switch
                    {
                        256 => HashAlgorithmName.SHA256,
                        384 => HashAlgorithmName.SHA384,
                        521 => HashAlgorithmName.SHA512,
                        _ => throw new ArgumentException("Invalid ECDSA key size")
                    };
                    break;
                default:
                    algorithmNameJws = JWSConstants.RS256;
                    algorithmName = HashAlgorithmName.SHA256;
                    break;
            }

            // Determine the algorithm
            if (hashAlgorithm != null) {
                switch (signer) {
                    case RSA:
                        // Allow set of hash algorithm
                        algorithmNameJws = hashAlgorithm.Value.Name switch
                        {
                            "SHA256" => useRSAPSS ? JWSConstants.PS256 : JWSConstants.RS256,
                            "SHA384" => useRSAPSS ? JWSConstants.PS384 : JWSConstants.RS384,
                            "SHA512" => useRSAPSS ? JWSConstants.PS512 : JWSConstants.RS512,
                            _ => throw new ArgumentException("Invalid RSA hash algorithm")
                        };
                        algorithmName = hashAlgorithm.Value;
                        break;
                    case ECDsa:
                        break;
                    default:
                        algorithmNameJws = JWSConstants.RS256;
                        algorithmName = hashAlgorithm.Value;
                        break;
                }
            }

            // return
            return new KeyTypeAlgorithmResult(algorithmNameJws, algorithmName.Value);
        }
    }

    /// <summary>
    /// Some result of the key type algorithm
    /// </summary>
    /// <param name="JwsName">JWS name</param>
    /// <param name="DotnetName">Dotnet name</param>
    public record class KeyTypeAlgorithmResult(string JwsName, HashAlgorithmName DotnetName);
}
