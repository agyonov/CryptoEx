using EdDSA.Utils;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace EdDSA.JOSE;
public class JOSESigner
{
    // The signing key
    protected readonly AsymmetricAlgorithm _signer;

    // Jws algorithm name
    protected readonly string _algorithmNameJws;

    // .NET algorithm name
    protected readonly HashAlgorithmName _algorithmName;

    // Possibli the certificate
    protected X509Certificate2? _certificate;

    // Some header 
    protected string? _header = null;

    // Some unprotected header 
    protected object? _unprotectedHeader = null;

    // JOSE protected data
    protected readonly List<string> _protecteds;

    // JOSE payload
    protected string? _payload = null;

    // The calculate signature
    protected readonly List<byte[]> _signatures;

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public JOSESigner(AsymmetricAlgorithm signer)
    {
        // Store
        _signer = signer;
        _signatures = new List<byte[]>();
        _protecteds = new List<string>();

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
    // Clear signature data
    public virtual void Clear()
    {
        _certificate = null;
        _header = null;
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
        PrepareHeader();

        // Form JOSE protected data - clear
        _payload = Base64UrlEncoder.Encode(payload);
        string _protected = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(_header ?? string.Empty));
        _protecteds.Add(_protected);
        string calc = $"{_protected}.{_payload}";
        if (_signer is RSA) {
            _signatures.Add(((RSA)_signer).SignData(Encoding.ASCII.GetBytes(calc), _algorithmName, RSASignaturePadding.Pkcs1));
        } else if (_signer is ECDsa) {
            _signatures.Add(((ECDsa)_signer).SignData(Encoding.ASCII.GetBytes(calc), _algorithmName));
        }
    }

    /// <summary>
    /// Encode JWS full or JWS flattened
    /// </summary>
    /// <param name="flattened">Set True for flattened, false - for full. Default is true</param>
    /// <returns>The encoded JWS</returns>
    public string Encode(bool flattened = true)
    {
        // Chec if flattened
        if (flattened) {
            return JsonSerializer.Serialize(new JWSFlattened
            {
                Payload = _payload,
                Protected = _protecteds.FirstOrDefault() ?? string.Empty,
                Header = _unprotectedHeader,
                Signature = Base64UrlEncoder.Encode(_signatures.FirstOrDefault() ?? Array.Empty<byte>())
            }, JOSEConstants.jsonOptions);
        } else {
            return JsonSerializer.Serialize(new JWS
            {
                Payload = _payload,
                Signatures = _signatures.Select((sigItem, index) =>
                    new JWSSignature
                    {
                        Protected = _protecteds[index],
                        Header = _unprotectedHeader,
                        Signature = Base64UrlEncoder.Encode(sigItem)
                    }).ToArray(),
            }, JOSEConstants.jsonOptions);
        }
    }

    /// <summary>
    /// Encode JWS in compact serialization
    /// </summary>
    /// <returns>The encoded JWS</returns>
    public string EncodeCompact()
        => $"{_protecteds.FirstOrDefault() ?? string.Empty}.{_payload}.{Base64UrlEncoder.Encode(_signatures.FirstOrDefault() ?? Array.Empty<byte>())}";

    // Prepare header values
    protected virtual void PrepareHeader(string? mimeType = null)
    {
        JWSHeader? jWSHeader;

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

        _header = JsonSerializer.Serialize(jWSHeader, JOSEConstants.jsonOptions);
    }

}
