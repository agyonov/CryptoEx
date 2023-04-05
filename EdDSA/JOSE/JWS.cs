using System.Text.Json.Serialization;

namespace EdDSA.JOSE;

public record class JWS
{
    [JsonPropertyName("payload")]
    public string? Payload { get; set; } = null;
    [JsonPropertyName("signatures")]
    public JWSSignature[] Signatures { get; set; } = Array.Empty<JWSSignature>();
}

public record class JWSFlattened
{
    [JsonPropertyName("payload")]
    public string? Payload { get; set; } = null;
    [JsonPropertyName("protected")]
    public string Protected { get; set; } = string.Empty;
    [JsonPropertyName("header")]
    public object? Header { get; set; } = null;
    [JsonPropertyName("signature")]
    public string Signature { get; set; } = string.Empty;
}
