using EdDSA.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

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

    // JOSE protected data
    protected string _protected = string.Empty;

    // JOSE payload
    protected string? _payload = null;

    // The calculate signature
    protected byte[] _signature = Array.Empty<byte>();

    public JOSESigner(AsymmetricAlgorithm signer)
    {
        // Store
        _signer = signer;

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

    public JOSESigner(AsymmetricAlgorithm signer, HashAlgorithmName hashAlgorithm)
    {
        // Store
        _signer = signer;

        // Determine the algorithm
        switch (signer) {
            case RSA:
                _algorithmNameJws = hashAlgorithm.Name switch
                {
                    "SHA256" => JOSEConstants.RS256,
                    "SHA384" => JOSEConstants.RS384,
                    "SHA512" => JOSEConstants.RS512,
                    _ => throw new ArgumentException("Invalid RSA hash algorithm")
                };
                _algorithmName = hashAlgorithm;
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

    // Clear signature data
    public void Clear() 
    {
        _certificate = null;
        _header = null;
        _protected = string.Empty;
        _payload = null;
        _signature = Array.Empty<byte>();
    }

    // Attach the signer's certificate to the JWS
    public void AttachSignersCertificate(X509Certificate2 cert)
    {
        _certificate = cert;
    }

    public virtual void Sign(ReadOnlySpan<byte> payload, string? mimeType = null)
    {
        // Prepare header
        PrepareHeader();

        // Form JOSE protected data - clear
        _payload = Base64UrlEncoder.Encode(payload);
        _protected = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(_header ?? string.Empty));
        string calc = $"{_protected}.{_payload}";
        if (_signer is RSA) {
            _signature = ((RSA)_signer).SignData(Encoding.ASCII.GetBytes(calc), _algorithmName, RSASignaturePadding.Pkcs1);
        } else if (_signer is ECDsa) {
            _signature = ((ECDsa)_signer).SignData(Encoding.ASCII.GetBytes(calc), _algorithmName);
        }
    }

    public virtual void SignDetached(ReadOnlyMemory<byte> payload, string? mimeType = null) { }

    public virtual string Encode()
        => JsonSerializer.Serialize(new JWS
        {
            Payload = _payload,
            Signatures = new JWSSignature[]
            {
                new JWSSignature
                {
                    Protected = _protected,
                    Signature = Base64UrlEncoder.Encode(_signature)
                }
            }
        }, JOSEConstants.jsonOptions);

    public virtual string EncodeSimple()
        => $"{_protected}.{_payload}.{Base64UrlEncoder.Encode(_signature)}";

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
