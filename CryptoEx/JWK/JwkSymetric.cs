using System.Text.Json.Serialization;

namespace CryptoEx.JWK;
public record JwkSymetric : Jwk
{
    /// <summary>
    /// Simetric key
    /// </summary>
    [JsonPropertyName("k")]
    public string? K { get; set; }
}
