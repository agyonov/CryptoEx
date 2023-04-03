using System.Text.Json.Serialization;

namespace EdDSA.JOSE;
public record class JWS
{
    [JsonPropertyName("payload")]
    public string? Payload { get; set; } = null;
    [JsonPropertyName("signatures")]
    public JWSSignature[] Signatures { get; set; } = Array.Empty<JWSSignature>();
}
