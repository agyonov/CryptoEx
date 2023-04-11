using CryptoEx.JWS.ETSI;
using System.Text.Json.Serialization;

namespace CryptoEx.JWS;

[JsonSerializable(typeof(JWS))]
[JsonSerializable(typeof(JWSFlattened))]
[JsonSerializable(typeof(JWSHeader))]
[JsonSerializable(typeof(JWSSignature))]
[JsonSerializable(typeof(ETSIDetachedParts))]
[JsonSerializable(typeof(ETSIHeader))]
[JsonSerializable(typeof(ETSISignatureTimestamp))]
[JsonSerializable(typeof(ETSITimestampContainer))]
[JsonSerializable(typeof(ETSITimestampToken))]
[JsonSerializable(typeof(ETSIUnprotectedHeader))]
internal partial class JWSSourceGenerationContext : JsonSerializerContext
{
}
