﻿using System.Text.Json.Serialization;

namespace CryptoEx.JWK;

/// <summary>
/// Ed keys as per https://tools.ietf.org/html/rfc8037
/// </summary>
public record JwkEd : Jwk
{
    /// <summary>
    /// Curve - Ed25519 or Ed448
    /// </summary>
    [JsonPropertyName("crv")]
    public string? Crv { get; set; }

    /// <summary>
    /// Public part, X coordinate on curve
    /// </summary>
    [JsonPropertyName("x")]
    public string? X { get; set; }

    /// <summary>
    /// Private key Ed
    /// </summary>
    [JsonPropertyName("d")]
    public string? D { get; set; }
}
