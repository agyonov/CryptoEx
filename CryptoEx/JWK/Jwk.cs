using System.Text.Json.Serialization;

namespace CryptoEx.JWK;

/// <summary>
/// A Jeson Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
/// </summary>
public record Jwk
{
    #region Common parameters

    /// <summary>
    /// (Key Type) Parameter - RSA, EC, Symmetric
    /// </summary>
    [JsonPropertyName("kty")]
    public string Kty { get; set; } = string.Empty;
    /// <summary>
    /// (Key Type) Parameter - 'sig', 'enc', oteher...
    /// </summary>
    [JsonPropertyName("use")]
    public string? Use { get; set; }
    /// <summary>
    /// (Key Operations) Parameter  - 'sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'
    /// </summary>
    [JsonPropertyName("key_ops")]
    public List<string>? KeyOps { get; set; }
    /// <summary>
    /// OPTIOANL  (Algorithm) Parameter - RS256, ES256, etc
    /// </summary>
    [JsonPropertyName("alg")]
    public string? Alg { get; set; }
    /// <summary>
    /// (Key ID) Parameter. OPTIONAL
    /// </summary>
    [JsonPropertyName("kid")]
    public string? Kid { get; set; }
    /// <summary>
    /// (X.509 URL) Parameter. OPTIONAL
    /// </summary>
    [JsonPropertyName("x5u")]
    public string? X5U { get; set; }
    /// <summary>
    /// (X.509 Certificate Chain) Parameter. OPTIONAL
    /// </summary>
    [JsonPropertyName("x5c")]
    public List<string>? X5C { get; set; }
    /// <summary>
    /// (X.509 Certificate SHA-1 Thumbprint) Parameter
    /// </summary>
    [JsonPropertyName("x5t")]
    public string? X5T { get; set; }
    /// <summary>
    /// (X.509 Certificate SHA-256 Thumbprint) Parameter
    /// </summary>
    [JsonPropertyName("x5t#S256")]
    public string? X5TSha256 { get; set; }

    #endregion Common parameters

    #region EC keys

    /// <summary>
    /// Curve - P-256, p-384, P-521
    /// </summary>
    [JsonPropertyName("crv")]
    public string? Crv { get; set; }

    /// <summary>
    /// Public part, X coordinate on curve
    /// </summary>
    [JsonPropertyName("x")]
    public string? X { get; set; }

    /// <summary>
    /// Public part, Y coordinate on curve
    /// </summary>
    [JsonPropertyName("y")]
    public string? Y { get; set; }

    /// <summary>
    /// Private key ECC
    /// Also, private part of RSA key - private exponent
    /// </summary>
    [JsonPropertyName("d")]
    public string? D { get; set; }

    #endregion EC keys

    #region RSA keys

    /// <summary>
    /// Modulus part of public key
    /// </summary>
    [JsonPropertyName("n")]
    public string? N { get; set; }

    /// <summary>
    /// Public exponent
    /// </summary>
    [JsonPropertyName("e")]
    public string? E { get; set; }

    /// <summary>
    /// (First Prime Factor) Parameter
    /// </summary>
    [JsonPropertyName("p")]
    public string? P { get; set; }

    /// <summary>
    ///  (Second Prime Factor) Parameter
    /// </summary>
    [JsonPropertyName("q")]
    public string? Q { get; set; }

    /// <summary>
    /// (First Factor CRT Exponent) Parameter
    /// </summary>
    [JsonPropertyName("dp")]
    public string? DP { get; set; }

    /// <summary>
    /// (Second Factor CRT Exponent) ParameterSecond factor CRT exponent
    /// </summary>
    [JsonPropertyName("dq")]
    public string? DQ { get; set; }

    /// <summary>
    ///(First CRT Coefficient) Parameter
    /// </summary>
    [JsonPropertyName("qi")]
    public string? QI { get; set; }

    /// <summary>
    /// (Other Primes Info) Parameter
    /// </summary>
    [JsonPropertyName("oth")]
    public List<OtherPrimeInfo>? Oth { get; set; }

    #endregion RSA keys

    #region Simetric key

    /// <summary>
    /// Simetric key
    /// </summary>
    [JsonPropertyName("k")]
    public string? K { get; set; }

    #endregion Simetric key
}

/// <summary>
/// For very edge usage of RSA keys. Not used very often
/// </summary>
public record OtherPrimeInfo
{
    /// <summary>
    ///  Prime Factor
    /// </summary>
    [JsonPropertyName("r")]
    public string? R { get; set; }

    /// <summary>
    ///  Factor CRT Exponent
    /// </summary>
    [JsonPropertyName("d")]
    public string? D { get; set; }

    /// <summary>
    ///  Factor CRT Coefficient
    /// </summary>
    [JsonPropertyName("t")]
    public string? T { get; set; }
}
