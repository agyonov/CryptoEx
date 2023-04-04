using System.Buffers.Text;
using System.Text;


namespace EdDSA.Utils;

/// <summary>
/// Encodes and Decodes strings as Base64Url encoding.
/// </summary>
public static class Base64UrlEncoder
{
    /// <summary>
    /// The following functions perform base64url encoding which differs from regular base64 encoding as follows
    /// * padding is skipped so the pad character '=' doesn't have to be percent encoded
    /// * the 62nd and 63rd regular base64 encoding characters ('+' and '/') are replace with ('-' and '_')
    /// The changes make the encoding alphabet file and URL safe.
    /// </summary>
    /// <param name="arg">string to encode.</param>
    /// <returns>Base64Url encoding of the UTF8 bytes.</returns>
    //public static string Encode(ReadOnlySpan<byte> arg)
    //{
    //    string wrk = Convert.ToBase64String(arg);
    //    StringBuilder sb = new StringBuilder(wrk.Length);

    //    for (int loop = 0; loop < wrk.Length; loop++) {
    //        sb.Append(wrk[loop] switch
    //        {
    //            '+' => '-',
    //            '/' => '_',
    //            _ => wrk[loop]
    //        });
    //    }

    //    int rem = sb.Length % 4;
    //    if (rem == 2) {
    //        sb.Remove(wrk.Length - 2, 2);
    //    } else if (rem == 3) {
    //        sb.Remove(wrk.Length - 1, 1);
    //    }

    //    return sb.ToString();
    //}

    /// <summary>
    /// Converts the specified string, base-64-url encoded to  bytes.</summary>
    /// <param name="str">base64Url encoded string.</param>
    /// <returns>UTF8 bytes.</returns>
    //public static byte[] Decode(string str)
    //{
    //    StringBuilder sb = new StringBuilder(str.Length);

    //    for (int loop = 0; loop < str.Length; loop++) {
    //        sb.Append(str[loop] switch
    //        {
    //            '-' => '+',
    //            '_' => '/',
    //            _ => str[loop]
    //        });
    //    }
    //    int rem = sb.Length % 4;
    //    if (rem == 2) {
    //        sb.Append("==");
    //    } else if (rem == 3) {
    //        sb.Append('=');
    //    }

    //    return Convert.FromBase64String(sb.ToString());
    //}


    /// <summary>
    /// Converts the specified string, base-64-url encoded to  bytes.</summary>
    /// <param name="str">base64Url encoded string.</param>
    /// <returns>UTF8 bytes.</returns>
    public static byte[] Decode(ReadOnlySpan<char> str)
    {
        //locals 
        int consumed, written;

        // calc some lengths
        int div = str.Length / 4;
        int rem = str.Length % 4;

        // the real length
        int len = (div * 3) + rem switch { 
            2 => 1,
            3 => 2,
            _ => 0
        };

        // Create the buffer
        byte[] result = new byte[len];
        Span<byte> resOver = result.AsSpan();
        Span<byte> buffer = stackalloc byte[4];

        // Cycle through the string
        for (int loop = 0; loop < div; loop++) 
        { 
            // Read 4 chars
            for (int rep = 0; rep < 4; rep++) {
                buffer[rep] = str[loop * 4 + rep] switch
                {
                    '_' => byteUnder,
                    '-' => byteMinus,
                    _ => Convert.ToByte(str[loop * 4 + rep])
                };
            }

            // Decode
            Base64.DecodeFromUtf8(buffer, resOver.Slice(loop*3, 3), out consumed, out written);
        }

        // Check rest
        switch (rem) {
            case 2:
                buffer[0] = str[(div * 4) + 0] switch
                {
                    '_' => byteUnder,
                    '-' => byteMinus,
                    _ => Convert.ToByte(str[(div * 4) + 0])
                };
                buffer[1] = str[(div * 4) + 1] switch
                {
                    '_' => byteUnder,
                    '-' => byteMinus,
                    _ => Convert.ToByte(str[(div * 4) + 1])
                };
                buffer[2] = byteEqual;
                buffer[3] = byteEqual;
                Base64.DecodeFromUtf8(buffer, resOver.Slice(div*3, 1), out consumed, out written);
                break;
            case 3:
                buffer[0] = str[(div * 4) + 0] switch
                {
                    '_' => byteUnder,
                    '-' => byteMinus,
                    _ => Convert.ToByte(str[(div * 4) + 0])
                };
                buffer[1] = str[(div * 4) + 1] switch
                {
                    '_' => byteUnder,
                    '-' => byteMinus,
                    _ => Convert.ToByte(str[(div * 4) + 1])
                };
                buffer[2] = str[(div * 4) + 2] switch
                {
                    '_' => byteUnder,
                    '-' => byteMinus,
                    _ => Convert.ToByte(str[(div * 4) + 2])
                };
                buffer[3] = byteEqual;
                Base64.DecodeFromUtf8(buffer, resOver.Slice(div * 3, 2), out consumed, out written);
                break;
            default:
                break;
        }

        // return
        return result;
    }

    /// <summary>
    /// The following functions perform base64url encoding .
    /// </summary>
    /// <param name="arg">The byte array to encode</param>
    /// <returns>Base64Url encoding as string</returns>
    public static string Encode(ReadOnlySpan<byte> arg)
    {
        // callc len
        int restMod = arg.Length % 3;
        int limitLoop = arg.Length / 3;

        // Define string holder
        char[] wrkBuffer = new char[(limitLoop * 4) + restMod switch { 
            1 => 2,
            2 => 3,
            _ => 0
        }];
        ReadOnlySpan<byte> src;

        // Loop
        int offset = 0;
        for (int loop = 0; loop < limitLoop; loop++, offset += 4) {
            // Get some
            src = arg.Slice(loop * 3, 3);

            // Encode
            wrkBuffer[offset + 0] = _base64UrlTable[src[0] >> 2];
            wrkBuffer[offset + 1] = _base64UrlTable[((src[0] & 0x03) << 4) | (src[1] >> 4)];
            wrkBuffer[offset + 2] = _base64UrlTable[((src[1] & 0x0f) << 2) | (src[2] >> 6)];
            wrkBuffer[offset + 3] = _base64UrlTable[src[2] & 0x3f];
        }

        // Check rest
        switch (restMod) {
            case 1:
                // Get some
                src = arg.Slice(arg.Length - 1, 1);

                // Encode
                wrkBuffer[offset + 0] = _base64UrlTable[src[0] >> 2];
                wrkBuffer[offset + 1] = _base64UrlTable[(src[0] & 0x03) << 4];

                break;

            case 2:
                // Get some
                src = arg.Slice(arg.Length - 2, 2);

                // Encode
                wrkBuffer[offset + 0] = _base64UrlTable[src[0] >> 2];
                wrkBuffer[offset + 1] = _base64UrlTable[((src[0] & 0x03) << 4) | (src[1] >> 4)];
                wrkBuffer[offset + 2] = _base64UrlTable[(src[1] & 0x0f) << 2];

                break;
            default:
                break;
        }

        // get back
        return new string(wrkBuffer);
    }

    /// <summary>
    /// Encoding table
    /// </summary>
    private static readonly char[] _base64UrlTable =
    {
            'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
            'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
            '0','1','2','3','4','5','6','7','8','9',
            '-',
            '_'
        };

    private static readonly byte byteMinus = Convert.ToByte('+');
    private static readonly byte byteUnder = Convert.ToByte('/');
    private static readonly byte byteEqual = Convert.ToByte('=');
}
