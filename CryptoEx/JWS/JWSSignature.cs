using System.Text.Json.Serialization;

namespace CryptoEx.JWS;
public record class JWSSignature
{
    [JsonPropertyName("protected")]
    public string Protected { get; set; } = string.Empty;
    [JsonPropertyName("header")]
    public object? Header { get; set; } = null;
    [JsonPropertyName("signature")]
    public string Signature { get; set; } = string.Empty;
}
