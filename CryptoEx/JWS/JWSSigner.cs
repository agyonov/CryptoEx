using CryptoEx.Utils;
using System.Collections.ObjectModel;
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

    // Possibli the certificate
    protected X509Certificate2? _certificate;

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


    /// <summary>
    /// A constructor without a private key, used for verification
    /// </summary>
    public JWSSigner()
    {
        // Store
        _signatures = new List<byte[]>();
        _protecteds = new List<string>();
        _header = string.Empty;
    }

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public JWSSigner(AsymmetricAlgorithm signer) : this()
    {
        // Store
        SetNewSigningKey(signer, null);
    }

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing and hash algorithm
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <param name="hashAlgorithm">Hash algorithm, mainly for RSA</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public JWSSigner(AsymmetricAlgorithm signer, HashAlgorithmName hashAlgorithm) : this()
    {
        // Store
        SetNewSigningKey(signer, hashAlgorithm);
    }

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing
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
    /// After calling 'Decode' and before calling 'Sign' next time you MUST call this method! 'Veryfy...' calls this method internally.
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
    }

    /// <summary>
    /// Change the signing key. This is useful for example when you want to sign with a new key.
    /// When you want to add a new signature, you set it with this method and then can use 'Sign' method to actually sign with
    /// the newly stetted key.
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <param name="hashAlgorithm">Hash algorithm, mainly for RSA</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public virtual void SetNewSigningKey(AsymmetricAlgorithm signer, HashAlgorithmName? hashAlgorithm = null)
    {
        // Store
        _signer = signer;
        _signerHmac = null;

        // Determine the algorithm
        switch (signer) {
            case RSA rsa:
                _algorithmNameJws = rsa.KeySize switch
                {
                    2048 => JWSConstants.RS256,
                    3072 => JWSConstants.RS384,
                    4096 => JWSConstants.RS512,
                    _ => throw new ArgumentException("Invalid RSA key size")
                };
                _algorithmName = rsa.KeySize switch
                {
                    2048 => HashAlgorithmName.SHA256,
                    3072 => HashAlgorithmName.SHA384,
                    4096 => HashAlgorithmName.SHA512,
                    _ => throw new ArgumentException("Invalid RSA key size")
                };
                break;
            case ECDsa ecdsa:
                _algorithmNameJws = ecdsa.KeySize switch
                {
                    256 => JWSConstants.ES256,
                    384 => JWSConstants.ES384,
                    521 => JWSConstants.ES512,
                    _ => throw new ArgumentException("Invalid ECDSA key size")
                };
                _algorithmName = ecdsa.KeySize switch
                {
                    256 => HashAlgorithmName.SHA256,
                    384 => HashAlgorithmName.SHA384,
                    521 => HashAlgorithmName.SHA512,
                    _ => throw new ArgumentException("Invalid ECDSA key size")
                };
                break;
            default:
                throw new ArgumentException("Invalid key type");
        }

        // Determine the algorithm
        if (hashAlgorithm != null) {
            switch (signer) {
                case RSA:
                    // Allow set of hash algorithm
                    _algorithmNameJws = hashAlgorithm.Value.Name switch
                    {
                        "SHA256" => JWSConstants.RS256,
                        "SHA384" => JWSConstants.RS384,
                        "SHA512" => JWSConstants.RS512,
                        _ => throw new ArgumentException("Invalid RSA hash algorithm")
                    };
                    _algorithmName = hashAlgorithm.Value;
                    break;
                case ECDsa:
                    break;
                default:
                    throw new ArgumentException("Invalid key type");
            }
        }
    }

    /// <summary>
    /// Change the signing key. This is useful for example when you want to sign with a new key.
    /// When you want to add a new signature, you set it with this method and then can use 'Sign' method to actually sign with
    /// the newly stetted key.
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public virtual void SetNewSigningKey(HMAC signer)
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
    /// </summary>
    /// <param name="cert">The certificate</param>
    /// <param name="additionalCertificates">The additional certificates to add to the signature</param>
    public void AttachSignersCertificate(X509Certificate2 cert, IReadOnlyList<X509Certificate2>? additionalCertificates = null)
    {
        _certificate = cert;
        _additionalCertificates = additionalCertificates;
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
    public virtual void Sign(ReadOnlySpan<byte> payload, string? mimeType = null, string? typHeaderparameter = null)
    {
        // Set it
        _signatureTypHeaderParameter = typHeaderparameter;

        // Prepare header
        PrepareHeader(mimeType);

        // Form JOSE protected data
        _payload = Base64UrlEncoder.Encode(payload);
        _protecteds.Add(_header);

        // Sign
        if (_signer != null) {
            switch (_signer) {
                case RSA rsa:
                    _signatures.Add(rsa.SignData(Encoding.ASCII.GetBytes($"{_header}.{_payload}"), _algorithmName, RSASignaturePadding.Pkcs1));
                    break;
                case ECDsa ecdsa:
                    _signatures.Add(ecdsa.SignData(Encoding.ASCII.GetBytes($"{_header}.{_payload}"), _algorithmName));
                    break;
                default:
                    throw new ArgumentException("Invalid key type.");
            };
        } else if (_signerHmac != null) {
            // HMAC case
            _signatures.Add(_signerHmac.ComputeHash(Encoding.ASCII.GetBytes($"{_header}.{_payload}")));
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
    public virtual bool Verify<T>(IReadOnlyList<object> keys, Func<T, bool>? resolutor = null) where T : JWSHeader
    {
        // Declare result
        bool result = true;
        HashAlgorithmName algorithmName;

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

                // Verify
                AsymmetricAlgorithm? aa = keys[loop] as AsymmetricAlgorithm;
                if (aa != null) {
                    switch (aa) {
                        case RSA rsa:
                            // Get algorithm name
                            algorithmName = headers[loop].Alg switch
                            {
                                JWSConstants.RS256 => HashAlgorithmName.SHA256,
                                JWSConstants.RS384 => HashAlgorithmName.SHA384,
                                JWSConstants.RS512 => HashAlgorithmName.SHA512,
                                _ => throw new ArgumentException($"Invalid RSA hash algorithm - {headers[loop].Alg}")
                            };

                            // Verify
                            result &= rsa.VerifyData(Encoding.ASCII.GetBytes($"{_protecteds[loop]}.{_payload}"), _signatures[loop], algorithmName, RSASignaturePadding.Pkcs1);
                            break;
                        case ECDsa ecdsa:
                            // Get algorithm name
                            algorithmName = headers[loop].Alg switch
                            {
                                JWSConstants.ES256 => HashAlgorithmName.SHA256,
                                JWSConstants.ES384 => HashAlgorithmName.SHA384,
                                JWSConstants.ES512 => HashAlgorithmName.SHA512,
                                _ => throw new ArgumentException($"Invalid ECDSA hash algorithm - {headers[loop].Alg}")
                            };

                            // Verify
                            result &= ecdsa.VerifyData(Encoding.ASCII.GetBytes($"{_protecteds[loop]}.{_payload}"), _signatures[loop], algorithmName);
                            break;
                        default:
                            throw new ArgumentException("Invalid key type. If you want to use some of PSxxx key types - please write descendant class of this class and override the current method...");
                    }
                } else {
                    // HMAC case
                    HMAC? hmac = keys[loop] as HMAC;

                    // Check
                    if (hmac != null) {
                        // Get algorithm name
                        algorithmName = headers[loop].Alg switch
                        {
                            JWSConstants.HS256 => HashAlgorithmName.SHA256,
                            JWSConstants.HS384 => HashAlgorithmName.SHA384,
                            JWSConstants.HS512 => HashAlgorithmName.SHA512,
                            _ => throw new ArgumentException($"Invalid HMAC hash algorithm - {headers[loop].Alg}")
                        };

                        // Verify
                        result &= hmac.ComputeHash(Encoding.ASCII.GetBytes($"{_protecteds[loop]}.{_payload}"))
                                      .SequenceEqual(_signatures[loop]);
                    } else {
                        throw new ArgumentException("Invalid key type.");
                    }
                }
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
    public string Encode(JWSEncodeTypeEnum type = JWSEncodeTypeEnum.Compact)
    {
        // Check it
        if (_signatures.Count > 1) {
            type = JWSEncodeTypeEnum.Full;
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
    public virtual ReadOnlyCollection<T> Decode<T>(ReadOnlySpan<char> signature, out byte[] payload) where T : JWSHeader
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
        // Load payload
        payload = _payload != null ? Base64UrlEncoder.Decode(_payload) : Array.Empty<byte>();

        // Return header
        return _protecteds.Select(p => JsonSerializer.Deserialize<T>(Base64UrlEncoder.Decode(p), JWSConstants.jsonOptions))
                          .Where(p => p != null)
                          .ToList()
                          .AsReadOnly()!;
    }

    // Decode compact encoded signature
    protected void DecodeCompact(ReadOnlySpan<char> signature)
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
    protected void DecodeFull(ReadOnlySpan<char> signature)
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

    // Prepare header values
    protected virtual void PrepareHeader(string? mimeType = null)
    {
        JWSHeader? jWSHeader;
        _header = string.Empty;

        if (string.IsNullOrEmpty(_algorithmNameJws)) {
            throw new ArgumentNullException(nameof(_algorithmNameJws));
        }

        if (_certificate == null) {
            jWSHeader = new JWSHeader
            {
                Alg = _algorithmNameJws,
                Cty = mimeType,
                Typ = _signatureTypHeaderParameter
            };
        } else {
            if (_additionalCertificates == null || _additionalCertificates.Count < 1) {
                jWSHeader = new JWSHeader
                {
                    Alg = _algorithmNameJws,
                    Cty = mimeType,
                    X5 = Base64UrlEncoder.Encode(_certificate.GetCertHash(HashAlgorithmName.SHA256)),
                    X5c = new string[] { Convert.ToBase64String(_certificate.RawData) },
                    Typ = _signatureTypHeaderParameter
                };
            } else {
                string[] strX5c = new string[_additionalCertificates.Count + 1];
                strX5c[0] = Convert.ToBase64String(_certificate.RawData);
                for (int loop = 0; loop < _additionalCertificates.Count; loop++) {
                    strX5c[loop + 1] = Convert.ToBase64String(_additionalCertificates[loop].RawData);
                }
                jWSHeader = new JWSHeader
                {
                    Alg = _algorithmNameJws,
                    Cty = mimeType,
                    X5 = Base64UrlEncoder.Encode(_certificate.GetCertHash(HashAlgorithmName.SHA256)),
                    X5c = strX5c,
                    Typ = _signatureTypHeaderParameter
                };
            }
        }

        // Serialize header
        using (MemoryStream ms = new(8192)) {
            JsonSerializer.Serialize(ms, jWSHeader, JWSConstants.jsonOptions);
            _header = Base64UrlEncoder.Encode(ms.ToArray());
        }
    }
}
