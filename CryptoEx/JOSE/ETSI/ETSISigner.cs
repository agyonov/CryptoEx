using CryptoEx.Utils;
using System.Globalization;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CryptoEx.JOSE.ETSI;
public class ETSISigner : JOSESigner
{
    // hashed data - used in detached mode
    protected byte[]? hashedData = null;

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
    public virtual void SignDetached(Stream attachement, string? optionalPayload = null, string mimeTypeAttachement = "octet-stream")
    {
        // Hash attachemnt
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

        // Prepare header
        PrepareHeader(mimeTypeAttachement);

        // Form JOSE protected data 
        if (optionalPayload != null) {
            _payload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(optionalPayload));
        }
        _protecteds.Add(_header);
        string calc = optionalPayload == null ? $"{_header}." : $"{_header}.{_payload}";
        if (_signer is RSA) {
            _signatures.Add(((RSA)_signer).SignData(Encoding.ASCII.GetBytes(calc), _algorithmName, RSASignaturePadding.Pkcs1));
        } else if (_signer is ECDsa) {
            _signatures.Add(((ECDsa)_signer).SignData(Encoding.ASCII.GetBytes(calc), _algorithmName));
        }
    }

    /// <summary>
    /// Validates crytical header values, for an ETSI signature
    /// </summary>
    /// <param name="header">The header</param>
    /// <returns>True - present and understood. Flase - other case</returns>
    public static bool ETSIResolutor(ETSIHeader header) 
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
                    } // If not null, then it is checked in detached verification
                    break;
                default:
                    return false;
            }
        }

        // All good
        return true;
    }

    // Prepare header values
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

        // Serialize header
        using (MemoryStream ms = new(8192)) {
            JsonSerializer.Serialize(ms, etsHeader, JOSEConstants.jsonOptions);
            _header = Base64UrlEncoder.Encode(ms.ToArray());
        }
    }
}
