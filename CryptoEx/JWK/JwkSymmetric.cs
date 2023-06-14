using System.Text.Json.Serialization;

namespace CryptoEx.JWK;

/// A Jeson Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
/// For symmetric keys
public record class JwkSymmetric : Jwk
{
    /// <summary>
    /// Simetric key
    /// </summary>
    [JsonPropertyName("k")]
    public string K { get; set; } = string.Empty;
}
