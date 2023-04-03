using EdDSA.Utils;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EdDSA.JOSE.ETSI;
public class ETSISigner : JOSESigner
{
    protected ETSIUnprotectedHeader? etsiUnprotected = null;

    public ETSISigner(AsymmetricAlgorithm signer) : base(signer)
    {
    }

    public ETSISigner(AsymmetricAlgorithm signer, HashAlgorithmName hashAlgorithm) : base(signer, hashAlgorithm)
    {
    }

    public override void Clear()
    {
        // Clear the base
        base.Clear();

        // Clear this
        etsiUnprotected = null;
    }

    // Encode as JWS full
    public override string Encode()
        => JsonSerializer.Serialize(new JWS
        {
            Payload = _payload,
            Signatures = new JWSSignature[]
            {
                new JWSSignature
                {
                    Protected = _protected,
                    Header = etsiUnprotected,
                    Signature = Base64UrlEncoder.Encode(_signature)
                }
            }
        }, JOSEConstants.jsonOptions);

    // Add timestamping
    public async Task AddTimestampAsync(Func<byte[], Task<byte[]>> funcAsync) 
    {
        byte[] prepSign = Encoding.ASCII.GetBytes(Base64UrlEncoder.Encode(_signature));
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
        etsiUnprotected = new ETSIUnprotectedHeader
        {
            EtsiU = new string[] { Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(theTimeStamp, JOSEConstants.jsonOptions))) }
        };
    }

    protected override void PrepareHeader(string? mimeType = null)
    {
        // check
        if (_certificate == null) {
            throw new Exception("Certificate can not be null");
        }

        ETSIHeader etsHeader = new ETSIHeader
        {
            Alg = _algorithmNameJws,
            Cty = mimeType,
            Kid = Convert.ToBase64String(_certificate.IssuerName.RawData),
            SigT = $"{DateTimeOffset.UtcNow:yyyy-MM-ddTHH:mm:ssZ}",
            X5 = Base64UrlEncoder.Encode(_certificate.GetCertHash(HashAlgorithmName.SHA256)),
            X5c = new string[] { Convert.ToBase64String(_certificate.RawData) }
        };

        _header = JsonSerializer.Serialize(etsHeader, JOSEConstants.jsonOptions);
    }
}
