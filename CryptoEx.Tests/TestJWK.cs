using CryptoEx.JWK;
using System.Text.Json;

namespace CryptoEx.Tests;

public class TestJWK
{
    public const string JWK_PUBLIC_1 =
        """
        {
         "kty":"EC",
         "crv":"P-256",
         "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
         "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
         "kid":"JWK_PUB_1"
        }
        """;

    public const string JWK_PUBLIC_2 =
        """
        {
        "kty":"RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e":"AQAB",
        "alg":"RS256",
        "kid":"2011-04-29"
        }
        """;

    public const string JWK_PRIVATE_1 =
        """
        {
        "kty":"EC",
        "crv":"P-256",
        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
        "use":"enc",
        "kid":"1"
        }
        """;

    public const string JWK_PRIVATE_2 =
        """
        {
        "kty":"RSA",
        "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e":"AQAB",
        "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
        "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
        "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
        "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
        "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
        "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
        "alg":"RS256",
        "kid":"2011-04-29"
        }
        """;

    public const string JWK_SYMMETRIC =
        """
        {
        "kty":"oct",
        "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        "kid":"HMAC_1"
        }
        """;

    [Fact(DisplayName = "Decode RSA key public one")]
    public void DecodeRSAPublic()
    {
        JwkRSA? jwk = JsonSerializer.Deserialize<Jwk>(JWK_PUBLIC_2, JwkConstants.jsonOptions) as JwkRSA;

        Assert.NotNull(jwk);
        Assert.Equal("RSA", jwk.Kty);
        Assert.Equal("AQAB", jwk.E);
        Assert.Equal("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jwk.N);
        Assert.Equal("2011-04-29", jwk.Kid);
    }

    [Fact(DisplayName = "Decode EC key public one")]
    public void DecodeECPublic()
    {
        JwkEc? jwk = JsonSerializer.Deserialize<Jwk>(JWK_PUBLIC_1, JwkConstants.jsonOptions) as JwkEc;

        Assert.NotNull(jwk);
        Assert.Equal("EC", jwk.Kty);
        Assert.Equal("P-256", jwk.Crv);
        Assert.Equal("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", jwk.X);
        Assert.Equal("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", jwk.Y);
        Assert.Equal("JWK_PUB_1", jwk.Kid);
    }

    [Fact(DisplayName = "Decode EC key private one")]
    public void DecodeECPrivate()
    {
        JwkEc? jwk = JsonSerializer.Deserialize<Jwk>(JWK_PRIVATE_1, JwkConstants.jsonOptions) as JwkEc;

        Assert.NotNull(jwk);
        Assert.Equal("EC", jwk.Kty);
        Assert.Equal("P-256", jwk.Crv);
        Assert.Equal("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", jwk.X);
        Assert.Equal("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", jwk.Y);
        Assert.Equal("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE", jwk.D);
        Assert.Equal("enc", jwk.Use);
        Assert.Equal("1", jwk.Kid);
    }

    [Fact(DisplayName = "Decode RSA key private one")]
    public void DecodeRSAPrivate()
    {
        JwkRSA? jwk = JsonSerializer.Deserialize<Jwk>(JWK_PRIVATE_2, JwkConstants.jsonOptions) as JwkRSA;

        Assert.NotNull(jwk);
        Assert.Equal("RSA", jwk.Kty);
        Assert.Equal("AQAB", jwk.E);
        Assert.Equal("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jwk.N);
        Assert.Equal("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q", jwk.D);
        Assert.Equal("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs", jwk.P);
        Assert.Equal("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk", jwk.Q);
        Assert.Equal("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0", jwk.DP);
        Assert.Equal("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk", jwk.DQ);
        Assert.Equal("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU", jwk.QI);
        Assert.Equal("RS256", jwk.Alg);
        Assert.Equal("2011-04-29", jwk.Kid);
    }

    [Fact(DisplayName = "Decode HMAC")]
    public void DecodeHMAC()
    {
        JwkSymmetric? jwk = JsonSerializer.Deserialize<Jwk>(JWK_SYMMETRIC, JwkConstants.jsonOptions) as JwkSymmetric;

        Assert.NotNull(jwk);
        Assert.Equal("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow", jwk.K);
        Assert.Equal("HMAC_1", jwk.Kid);
    }
}
