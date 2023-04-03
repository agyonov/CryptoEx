using EdDSA.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

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

        ETSIHeader etsHeader =  new ETSIHeader
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
