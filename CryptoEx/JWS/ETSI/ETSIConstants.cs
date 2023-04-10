namespace CryptoEx.JWS.ETSI;

//  Some ETSI constants as defined in ETSI TS 119 182-1
public static class ETSIConstants
{
    // As of ETSI TS 119 182-1 p.5.2.8.2  - Not used very often by us
    public const string ETSI_DETACHED_PARTS_HTTP_HEADERS = "http://uri.etsi.org/19182/HttpHeaders";

    // As of ETSI TS 119 182-1 p.5.2.8.3.2  - Not used very often by us
    public const string ETSI_DETACHED_PARTS_OBJECT_URI = "http://uri.etsi.org/19182/ObjectIdByURI";

    // As of ETSI TS 119 182-1 p.5.2.8.3.3   - USED very often by us
    public const string ETSI_DETACHED_PARTS_OBJECT_HASH = "http://uri.etsi.org/19182/ObjectIdByURIHash";

    // Possible value of HashM property - As of ETSI TS 119 182-1 p.5.2.8.3.3
    public const string SHA256 = "S256";

    // Possible value of HashM property - As of ETSI TS 119 182-1 p.5.2.8.3.3
    public const string SHA384 = "S384";

    // Possible value of HashM property - As of ETSI TS 119 182-1 p.5.2.8.3.3
    public const string SHA512 = "S512";
}
