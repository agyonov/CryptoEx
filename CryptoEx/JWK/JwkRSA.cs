using System.Text.Json.Serialization;

namespace CryptoEx.JWK;

/// <summary>
/// A Jeson Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
/// For RSA keys
/// </summary>
public record class JwkRSA : Jwk
{
    /// <summary>
    /// Modulus part of public key
    /// </summary>
    [JsonPropertyName("n")]
    public string? N { get; set; } = null;

    /// <summary>
    /// Public exponent
    /// </summary>
    [JsonPropertyName("e")]
    public string? E { get; set; } = null;

    /// <summary>
    /// Private part of RSA key - private exponent
    /// </summary>
    [JsonPropertyName("d")]
    public string? D { get; set; } = null;

    /// <summary>
    /// (First Prime Factor) Parameter
    /// </summary>
    [JsonPropertyName("p")]
    public string? P { get; set; } = null;

    /// <summary>
    ///  (Second Prime Factor) Parameter
    /// </summary>
    [JsonPropertyName("q")]
    public string? Q { get; set; } = null;

    /// <summary>
    /// (First Factor CRT Exponent) Parameter
    /// </summary>
    [JsonPropertyName("dp")]
    public string? DP { get; set; } = null;

    /// <summary>
    /// (Second Factor CRT Exponent) ParameterSecond factor CRT exponent
    /// </summary>
    [JsonPropertyName("dq")]
    public string? DQ { get; set; } = null;

    /// <summary>
    ///(First CRT Coefficient) Parameter
    /// </summary>
    [JsonPropertyName("qi")]
    public string? QI { get; set; } = null;

    /// <summary>
    /// (Other Primes Info) Parameter
    /// </summary>
    [JsonPropertyName("oth")]
    public List<OtherPrimeInfo>? Oth { get; set; } = null;
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
