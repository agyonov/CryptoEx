using System.Text.Json.Serialization;

namespace CryptoEx.JWK;

/// <summary>
/// A Jeson Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
/// For EC keys
/// </summary>
public record class JwkEc : Jwk
{
    /// <summary>
    /// Curve - P-256, p-384, P-521
    /// </summary>
    [JsonPropertyName("crv")]
    public string Crv { get; set; } = string.Empty;

    /// <summary>
    /// Public part, X coordinate on curve
    /// </summary>
    [JsonPropertyName("x")]
    public string X { get; set; } = string.Empty;

    /// <summary>
    /// Public part, Y coordinate on curve
    /// </summary>
    [JsonPropertyName("y")]
    public string Y { get; set; } = string.Empty;

    /// <summary>
    /// Private key ECC
    /// </summary>
    [JsonPropertyName("d")]
    public string? D { get; set; } = null;
}
