using EdDSA.Utils;
using System.Security.Cryptography;
using System.Text.Json;

namespace EdDSA.JOSE.ETSI;
public class ETSISigner : JOSESigner
{
    public ETSISigner(AsymmetricAlgorithm signer) : base(signer)
    {
    }

    public ETSISigner(AsymmetricAlgorithm signer, HashAlgorithmName hashAlgorithm) : base(signer, hashAlgorithm)
    {
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
