using System.Text.Json.Serialization;

namespace CryptoEx.JWS.ETSI;


public record class ETSIHeader : JWSHeader
{
    [JsonPropertyName("sigT")]
    public string SigT { get; set; } = string.Empty;
    [JsonPropertyName("adoTst")]
    public ETSITimestampContainer? AdoTst { get; set; } = null;
    [JsonPropertyName("sigD")]
    public ETSIDetachedParts? SigD { get; set; } = null;
    [JsonPropertyName("crit")]
    public override string[]? Crit
    {
        get {
            List<string> build = new List<string>
            {
                "sigT"
            };
            if (SigD != null) {
                build.Add("sigD");
            }
            if (AdoTst != null) {
                build.Add("adoTst");
            }
            return build.ToArray();
        }

        set {
            // Do nothing, but store for possible use in resolutor function
            _Crit = value;
        }
    }
    protected internal string[]? _Crit = null;
}
