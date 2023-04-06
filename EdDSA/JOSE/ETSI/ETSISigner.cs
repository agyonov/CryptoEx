using EdDSA.Utils;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EdDSA.JOSE.ETSI;
public class ETSISigner : JOSESigner
{
    // hashed data - used in detached mode
    protected byte[]? hashedData = null;

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
    /// </summary>
    public override void Clear()
    {
        // Clear hashed data
        hashedData = null;

        // call parent
        base.Clear();
    }

    /// <summary>
    /// Add timestamping
    /// </summary>
    /// <param name="funcAsync">Async function that calls Timestamping server, with input data and returns 
    /// response from the server
    /// </param>
    public async Task AddTimestampAsync(Func<byte[], Task<byte[]>> funcAsync)
    {
        byte[] prepSign = Encoding.ASCII.GetBytes(Base64UrlEncoder.Encode(_signatures.FirstOrDefault() ?? Array.Empty<byte>()));
        byte[] tStamp = await funcAsync(prepSign);

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
            EtsiU = new string[] { Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(theTimeStamp, JOSEConstants.jsonOptions))) }
        };
    }

    /// <summary>
    /// Digitally sign the attachement, optional payload and protected header in detached mode
    /// </summary>
    /// <param name="attachement">The attached data (file) </param>
    /// <param name="optionalPayload">The optional payload. SHOUD BE JSON STRING.</param>
    /// <param name="mimeTypeAttachement">Optionally mimeType. Defaults to "octet-stream"</param>
    public virtual void SignDetached(ReadOnlySpan<byte> attachement, string? optionalPayload = null, string mimeTypeAttachement = "octet-stream")
    {
        // Hash attachemnt
        using (HashAlgorithm hAlg = SHA512.Create()) {
            // Hash attachemnt
            hashedData = hAlg.ComputeHash(Encoding.ASCII.GetBytes(Base64UrlEncoder.Encode(attachement)));

            // Prepare header
            PrepareHeader(mimeTypeAttachement);

            // Form JOSE protected data 
            if (optionalPayload != null) {
                _payload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(optionalPayload));
            }
            string _protected = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(_header ?? string.Empty));
            _protecteds.Add(_protected);
            string calc = optionalPayload == null ? $"{_protected}." : $"{_protected}.{_payload}";
            if (_signer is RSA) {
                _signatures.Add(((RSA)_signer).SignData(Encoding.ASCII.GetBytes(calc), _algorithmName, RSASignaturePadding.Pkcs1));
            } else if (_signer is ECDsa) {
                _signatures.Add(((ECDsa)_signer).SignData(Encoding.ASCII.GetBytes(calc), _algorithmName));
            }
        }
    }

    // Prepare header values
    protected override void PrepareHeader(string? mimeType = null)
    {
        // check
        if (_certificate == null) {
            throw new Exception("Certificate can not be null");
        }

        // header ETSI
        ETSIHeader etsHeader;

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
            etsHeader = new ETSIHeader
            {
                Alg = _algorithmNameJws,
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
        }

        // Encode
        _header = JsonSerializer.Serialize(etsHeader, JOSEConstants.jsonOptions);
    }
}
