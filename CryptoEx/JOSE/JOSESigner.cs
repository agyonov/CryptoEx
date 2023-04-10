using CryptoEx.Utils;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace CryptoEx.JOSE;
public class JOSESigner
{
    // The signing key
    protected readonly AsymmetricAlgorithm? _signer;

    // Jws algorithm name
    protected readonly string? _algorithmNameJws;

    // .NET algorithm name
    protected readonly HashAlgorithmName _algorithmName;

    // Possibli the certificate
    protected X509Certificate2? _certificate;

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


    /// <summary>
    /// A constructor without a private key, used for verification
    /// </summary>
    public JOSESigner()
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
    public JOSESigner(AsymmetricAlgorithm signer) : base()
    {
        // Store
        _signer = signer;
        _signatures = new List<byte[]>();
        _protecteds = new List<string>();
        _header = string.Empty;

        // Determine the algorithm
        switch (signer) {
            case RSA rsa:
                _algorithmNameJws = rsa.KeySize switch
                {
                    2048 => JOSEConstants.RS256,
                    3072 => JOSEConstants.RS384,
                    4096 => JOSEConstants.RS512,
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
                    256 => JOSEConstants.ES256,
                    384 => JOSEConstants.ES384,
                    521 => JOSEConstants.ES512,
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
    }

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing and hash algorithm
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <param name="hashAlgorithm">Hash algorithm, mainly for RSA</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public JOSESigner(AsymmetricAlgorithm signer, HashAlgorithmName hashAlgorithm) : this(signer)
    {
        // Determine the algorithm
        switch (signer) {
            case RSA:
                // Allow set of hash algorithm
                _algorithmNameJws = hashAlgorithm.Name switch
                {
                    "SHA256" => JOSEConstants.RS256,
                    "SHA384" => JOSEConstants.RS384,
                    "SHA512" => JOSEConstants.RS512,
                    _ => throw new ArgumentException("Invalid RSA hash algorithm")
                };
                _algorithmName = hashAlgorithm;
                break;
            case ECDsa:
                break;
            default:
                throw new ArgumentException("Invalid key type");
        }
    }

    /// <summary>
    /// Clear some data.
    /// Every thing except the signer and the HashAlgorithmName!
    /// </summary>
    public virtual void Clear()
    {
        _certificate = null;
        _header = string.Empty;
        _protecteds.Clear();
        _payload = null;
        _signatures.Clear();
        _unprotectedHeader = null;
    }

    /// <summary>
    /// Attach the signer's certificate to the JWS. ONLY public part of the certificate is used.
    /// This is optional and is only used to add the x5c, x5t header
    /// </summary>
    /// <param name="cert">The certificate</param>
    public void AttachSignersCertificate(X509Certificate2 cert)
    {
        _certificate = cert;
    }

    /// <summary>
    /// Digitally sign the payload and protected header
    /// </summary>
    /// <param name="payload">The payload</param>
    /// <param name="mimeType">Optionally the mime type of the header</param>
    public virtual void Sign(ReadOnlySpan<byte> payload, string? mimeType = null)
    {
        // Prepare header
        PrepareHeader(mimeType);

        // Form JOSE protected data
        _payload = Base64UrlEncoder.Encode(payload);
        _protecteds.Add(_header);

        // Sign
        switch (_signer) {
            case RSA rsa:
                _signatures.Add(rsa.SignData(Encoding.ASCII.GetBytes($"{_header}.{_payload}"), _algorithmName, RSASignaturePadding.Pkcs1));
                break;
            case ECDsa ecdsa:
                _signatures.Add(ecdsa.SignData(Encoding.ASCII.GetBytes($"{_header}.{_payload}"), _algorithmName));
                break;
            default:
                if (_signer == null) {
                    throw new ArgumentNullException(nameof(_algorithmNameJws));
                } else {
                    throw new ArgumentException("Invalid key type.  If you want to use some of HSxxx or PSxxx key types - please write descendant class of this class and override the current method...");
                }
        };
    }

    /// <summary>
    /// Verify the JWS
    /// </summary>
    /// <typeparam name="T">Must be descendant from the JWSHeader record. Shall hold data about protected headers of the JWS.
    /// For example, it may be ETSI JWS header, or some other header, which is used in the JWS.
    /// </typeparam>
    /// <param name="publicKeys">Public keys to use for verification. MUST correspond to each of the JWS headers in the JWS, returned by te Decode method!</param>
    /// <param name="resolutor">Resolutor if "Cryt" header parameter if it EXISTS in any of the JWS headers in the JWS, returned by te Decode method!
    /// Please provide DECENT resolutor, as this is a SECURITY issue! You may read https://www.rfc-editor.org/rfc/rfc7515#section-4.1.10 for more information.
    /// You may also have a look at the ETSISigner class in the current project, for an example of a resolutor.
    /// </param>
    /// <returns>True / false = valid / invalid signature check</returns>
    /// <exception cref="ArgumentException">Some issues exists with the arguments and/or keys provided to this method</exception>
    public virtual bool Verify<T>(List<AsymmetricAlgorithm> publicKeys, Func<T, bool>? resolutor = null) where T : JWSHeader
    {
        // Declare result
        bool result = true;
        HashAlgorithmName algorithmName;

        // Get the headers, from the protected data! 
        List<T> headers = _protecteds.Select(p => JsonSerializer.Deserialize<T>(Base64UrlEncoder.Decode(p), JOSEConstants.jsonOptions))
                                                .Where(p => p != null)
                                                .ToList()!;

        // Check the number of signatures
        if (headers.Count != _protecteds.Count || headers.Count != publicKeys.Count) {
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
            switch (publicKeys[loop]) {
                case RSA rsa:
                    // Get algorithm name
                    algorithmName = headers[loop].Alg switch
                    {
                        JOSEConstants.RS256 => HashAlgorithmName.SHA256,
                        JOSEConstants.RS384 => HashAlgorithmName.SHA384,
                        JOSEConstants.RS512 => HashAlgorithmName.SHA512,
                        _ => throw new ArgumentException($"Invalid RSA hash algorithm - {headers[loop].Alg}")
                    };

                    // Verify
                    result &= rsa.VerifyData(Encoding.ASCII.GetBytes($"{_protecteds[loop]}.{_payload}"), _signatures[loop], algorithmName, RSASignaturePadding.Pkcs1);
                    break;
                case ECDsa ecdsa:
                    // Get algorithm name
                    algorithmName = headers[loop].Alg switch
                    {
                        JOSEConstants.ES256 => HashAlgorithmName.SHA256,
                        JOSEConstants.ES384 => HashAlgorithmName.SHA384,
                        JOSEConstants.ES512 => HashAlgorithmName.SHA512,
                        _ => throw new ArgumentException($"Invalid ECDSA hash algorithm - {headers[loop].Alg}")
                    };

                    // Verify
                    result &= ecdsa.VerifyData(Encoding.ASCII.GetBytes($"{_protecteds[loop]}.{_payload}"), _signatures[loop], algorithmName);
                    break;
                default:
                    throw new ArgumentException("Invalid key type. If you want to use some of HSxxx or PSxxx key types - please write descendant class of this class and override the current method...");
            }
        }

        return result;
    }

    /// <summary>
    /// Encode JWS 
    /// </summary>
    /// <param name="type">Type of JWS encoding. Default is Compact</param>
    /// <returns>The encoded JWS</returns>
    /// <exception cref="ArgumentException">Unknow enoding type</exception>
    public string Encode(JOSEEncodeTypeEnum type = JOSEEncodeTypeEnum.Compact)
    {
        // Enoce it
        return type switch
        {
            JOSEEncodeTypeEnum.Compact =>
                $"{_protecteds.FirstOrDefault() ?? string.Empty}.{_payload}.{Base64UrlEncoder.Encode(_signatures.FirstOrDefault() ?? Array.Empty<byte>())}",
            JOSEEncodeTypeEnum.Flattened =>
                 JsonSerializer.Serialize(new JWSFlattened
                 {
                     Payload = _payload,
                     Protected = _protecteds.FirstOrDefault() ?? string.Empty,
                     Header = _unprotectedHeader,
                     Signature = Base64UrlEncoder.Encode(_signatures.FirstOrDefault() ?? Array.Empty<byte>())
                 }, JOSEConstants.jsonOptions),
            JOSEEncodeTypeEnum.Full =>
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
                }, JOSEConstants.jsonOptions),
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
        return _protecteds.Select(p => JsonSerializer.Deserialize<T>(Base64UrlEncoder.Decode(p), JOSEConstants.jsonOptions))
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
            int indexTwo = signature.Slice(index + 1).IndexOf('.');
            if (indexTwo < -1) {
                return;
            } else {
                // Add protected
                _payload = signature.Slice(index + 1, indexTwo).ToString();
            }

            // Get signature
            if (indexTwo + 1 < signature.Length) {
                _signatures.Add(Base64UrlEncoder.Decode(signature.Slice(indexTwo + 1).ToString()));
            }
        }
    }

    // Decode flattened or full encoded signature
    protected void DecodeFull(ReadOnlySpan<char> signature)
    {
        // Firts check if we have "flattened" encoded signature
        JWSFlattened? resFalttened = JsonSerializer.Deserialize<JWSFlattened>(signature, JOSEConstants.jsonOptions);
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
        JWS? res = JsonSerializer.Deserialize<JWS>(signature, JOSEConstants.jsonOptions);
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
                Cty = mimeType
            };
        } else {
            jWSHeader = new JWSHeader
            {
                Alg = _algorithmNameJws,
                Cty = mimeType,
                Kid = Convert.ToBase64String(_certificate.IssuerName.RawData),
                X5 = Base64UrlEncoder.Encode(_certificate.GetCertHash(HashAlgorithmName.SHA256)),
                X5c = new string[] { Convert.ToBase64String(_certificate.RawData) }
            };
        }

        // Serialize header
        using (MemoryStream ms = new(8192)) {
            JsonSerializer.Serialize(ms, jWSHeader, JOSEConstants.jsonOptions);
            _header = Base64UrlEncoder.Encode(ms.ToArray());
        }
    }
}
