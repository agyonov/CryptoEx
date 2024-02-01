using CryptoEx.JWS.ETSI;
using System.Text.Json.Serialization;

namespace CryptoEx.JWS;

[JsonSourceGenerationOptions(WriteIndented = false, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
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
[JsonSerializable(typeof(ETSIUnprotectedHeader))]
[JsonSerializable(typeof(ETSIPkiOb))]
[JsonSerializable(typeof(ETSIxValItem))]
[JsonSerializable(typeof(ETSIxVals))]
[JsonSerializable(typeof(ETSIrVal))]
[JsonSerializable(typeof(ETSIrVals))]
[JsonSerializable(typeof(JWK.OtherPrimeInfo))]
[JsonSerializable(typeof(JWK.Jwk))]
[JsonSerializable(typeof(JWK.JwkSet))]
[JsonSerializable(typeof(JWK.JwkEc))]
[JsonSerializable(typeof(JWK.JwkRSA))]
[JsonSerializable(typeof(JWK.JwkSymmetric))]
[JsonSerializable(typeof(JWK.JwkEd))]
internal partial class JWSSourceGenerationContext : JsonSerializerContext
{
}
