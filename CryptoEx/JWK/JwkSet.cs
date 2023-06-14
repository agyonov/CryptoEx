using System.Text.Json.Serialization;

namespace CryptoEx.JWK;

/// <summary>
/// JWK Set
/// </summary>
public record class JwkSet
{
    /// <summary>
    /// Keys
    /// </summary>
    [JsonPropertyName("keys")]
    public List<Jwk> Keys { get; set; } = new();
}
