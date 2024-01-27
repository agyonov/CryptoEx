using CryptoEx.JWS;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoEx.JWK;

/// <summary>
/// Converter for JWK <-- --> Json
/// </summary>
public class JwkConverter : JsonConverter<Jwk>
{
    public const string JwkType = "kty";

    public override void Write(Utf8JsonWriter writer, Jwk value, JsonSerializerOptions options)
    {
        // What we have
        switch (value) {
            case JwkRSA rsa:
                JsonSerializer.Serialize(writer, rsa, JWSSourceGenerationContext.Default.JwkRSA);
                break;
            case JwkEc ec:
                JsonSerializer.Serialize(writer, ec, JWSSourceGenerationContext.Default.JwkEc);
                break;
            case JwkEd ed:
                JsonSerializer.Serialize(writer, ed, JWSSourceGenerationContext.Default.JwkEd);
                break;
            case JwkSymmetric hmac:
                JsonSerializer.Serialize(writer, hmac, JWSSourceGenerationContext.Default.JwkSymmetric);
                break;
            default:
                JsonSerializer.Serialize(writer, value, JWSSourceGenerationContext.Default.Jwk);
                break;
        }
    }

    public override Jwk? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        // The discriminator
        string? discValue = null;

        // Create second reader - it is value type
        Utf8JsonReader cRreader = reader;

        // Befin parsing
        if (cRreader.TokenType != JsonTokenType.StartObject) {
            throw new JsonException("Json reader is not it initial state.");
        }

        // cycle
        while (cRreader.Read()) {
            // Check name
            if (cRreader.TokenType == JsonTokenType.PropertyName) {
                // Get name
                var pName = cRreader.GetString();

                // Try go to vale
                if (cRreader.Read()) {
                    // Yes it is the discriminator
                    if (string.Compare(pName, JwkType, true) == 0) {
                        // Check value
                        if (cRreader.TokenType == JsonTokenType.String) {
                            // Get value
                            discValue = cRreader.GetString();
                            break;
                        } else {
                            throw new JsonException($"The type discriminator \"{JwkType}\" for type {typeToConvert.Name} is not a string property! Please provide the type discriminator \"{JwkType}\" as string property.");
                        }
                    } else {
                        // Try Skip value
                        cRreader.Skip();
                    }
                } else {
                    break;
                }
            }
        }

        // Check read valie
        if (string.IsNullOrWhiteSpace(discValue)) {
            throw new JsonException($"The type discriminator \"{JwkType}\" for type {typeToConvert.Name} is not present as a property! Please provide the type discriminator \"{JwkType}\" as property.");
        }

        // parse it
        Jwk? baseClass = discValue switch
        {
            JwkConstants.EC => JsonSerializer.Deserialize(ref reader, JWSSourceGenerationContext.Default.JwkEc),
            JwkConstants.RSA => JsonSerializer.Deserialize(ref reader, JWSSourceGenerationContext.Default.JwkRSA),
            JwkConstants.OCT => JsonSerializer.Deserialize(ref reader, JWSSourceGenerationContext.Default.JwkSymmetric),
            JwkConstants.OKP => JsonSerializer.Deserialize(ref reader, JWSSourceGenerationContext.Default.JwkEd),
            _ => null
        };

        // return
        return baseClass;
    }
}
