using System.Buffers.Text;

namespace CryptoEx.Utils;

/// <summary>
/// Encodes and Decodes strings as Base64Url encoding.
/// </summary>
public static class Base64UrlEncoder
{
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
        int len = (div * 3) + rem switch
        {
            2 => 1,
            3 => 2,
            _ => 0
        };

        // Create the buffer
        byte[] result = new byte[len];
        Span<byte> resOver = result.AsSpan();
        Span<byte> buffer = stackalloc byte[4];

        // Cycle through the string
        for (int loop = 0; loop < div; loop++) {
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
            Base64.DecodeFromUtf8(buffer, resOver.Slice(loop * 3, 3), out consumed, out written);
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
                Base64.DecodeFromUtf8(buffer, resOver.Slice(div * 3, 1), out consumed, out written);
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
    /// Converts the specified string, base-64-url encoded to  bytes.</summary>
    /// <param name="str">base64Url encoded string.</param>
    /// <returns>UTF8 bytes.</returns>
    public static void Decode(TextReader str, Stream result)
    {
        //locals 
        int consumed, written;

        // Create the buffer
        Span<char> nextChar = stackalloc char[4];
        Span<byte> resOver = stackalloc byte[3];
        Span<byte> buffer = stackalloc byte[4];

        // Cycle through the string
        while (true) {
            // Read 4 chars
            consumed = str.Read(nextChar);

            // See what we got
            switch (consumed) {
                case 0:
                    // flush
                    result.Flush();

                    return;
                case 2:
                    buffer[0] = nextChar[0] switch
                    {
                        '_' => byteUnder,
                        '-' => byteMinus,
                        _ => Convert.ToByte(nextChar[0])
                    };
                    buffer[1] = nextChar[1] switch
                    {
                        '_' => byteUnder,
                        '-' => byteMinus,
                        _ => Convert.ToByte(nextChar[1])
                    };
                    buffer[2] = byteEqual;
                    buffer[3] = byteEqual;

                    Base64.DecodeFromUtf8(buffer, resOver, out consumed, out written);

                    // Write
                    result.Write(resOver[..1]);

                    break;
                case 3:
                    buffer[0] = nextChar[0] switch
                    {
                        '_' => byteUnder,
                        '-' => byteMinus,
                        _ => Convert.ToByte(nextChar[0])
                    };
                    buffer[1] = nextChar[1] switch
                    {
                        '_' => byteUnder,
                        '-' => byteMinus,
                        _ => Convert.ToByte(nextChar[1])
                    };
                    buffer[2] = nextChar[2] switch
                    {
                        '_' => byteUnder,
                        '-' => byteMinus,
                        _ => Convert.ToByte(nextChar[2])
                    };
                    buffer[3] = byteEqual;

                    Base64.DecodeFromUtf8(buffer, resOver, out consumed, out written);

                    // Write
                    result.Write(resOver[..2]);
                    break;
                case 4:
                    for (int rep = 0; rep < 4; rep++) {
                        buffer[rep] = nextChar[rep] switch
                        {
                            '_' => byteUnder,
                            '-' => byteMinus,
                            _ => Convert.ToByte(nextChar[rep])
                        };
                    }

                    // Decode
                    Base64.DecodeFromUtf8(buffer, resOver, out consumed, out written);
                    // Write
                    result.Write(resOver);

                    break;
                default:
                    throw new Exception("Invalid Base64Url string");
            }
        }
    }

    /// <summary>
    /// Converts the specified string, base-64-url encoded to  bytes.</summary>
    /// <param name="str">base64Url encoded string.</param>
    /// <returns>UTF8 bytes.</returns>
    public async static Task DecodeAsync(TextReader str, Stream result, CancellationToken ct = default)
    {
        //locals 
        int consumed;

        // Create the buffer
        char[] nextChar = new char[4];
        byte[] resOver = new byte[3];
        byte[] buffer = new byte[4];

        // Cycle through the string
        while (true) {
            // Read 4 chars
            consumed = await str.ReadAsync(nextChar, ct);

            // See what we got
            switch (consumed) {
                case 0:
                    // flush
                    await result.FlushAsync(ct);

                    return;
                case 2:
                    buffer[0] = nextChar[0] switch
                    {
                        '_' => byteUnder,
                        '-' => byteMinus,
                        _ => Convert.ToByte(nextChar[0])
                    };
                    buffer[1] = nextChar[1] switch
                    {
                        '_' => byteUnder,
                        '-' => byteMinus,
                        _ => Convert.ToByte(nextChar[1])
                    };
                    buffer[2] = byteEqual;
                    buffer[3] = byteEqual;

                    _ = Base64.DecodeFromUtf8(buffer, resOver, out _, out _);

                    // Write
                    await result.WriteAsync(resOver[..1], ct);

                    break;
                case 3:
                    buffer[0] = nextChar[0] switch
                    {
                        '_' => byteUnder,
                        '-' => byteMinus,
                        _ => Convert.ToByte(nextChar[0])
                    };
                    buffer[1] = nextChar[1] switch
                    {
                        '_' => byteUnder,
                        '-' => byteMinus,
                        _ => Convert.ToByte(nextChar[1])
                    };
                    buffer[2] = nextChar[2] switch
                    {
                        '_' => byteUnder,
                        '-' => byteMinus,
                        _ => Convert.ToByte(nextChar[2])
                    };
                    buffer[3] = byteEqual;

                    _ = Base64.DecodeFromUtf8(buffer, resOver, out _, out _);

                    // Write
                    await result.WriteAsync(resOver[..2], ct);

                    break;
                case 4:
                    for (int rep = 0; rep < 4; rep++) {
                        buffer[rep] = nextChar[rep] switch
                        {
                            '_' => byteUnder,
                            '-' => byteMinus,
                            _ => Convert.ToByte(nextChar[rep])
                        };
                    }

                    // Decode
                    _ = Base64.DecodeFromUtf8(buffer, resOver, out _, out _);

                    // Write
                    await result.WriteAsync(resOver, ct);

                    break;
                default:
                    throw new Exception("Invalid Base64Url string");
            }

            // Check
            if (ct.IsCancellationRequested) {
                return;
            }
        }
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
        char[] wrkBuffer = new char[(limitLoop * 4) + restMod switch
        {
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
    /// The following functions perform base64url encoding .
    /// </summary>
    /// <param name="arg">The stream to encode</param>
    /// <param name="result">The stream to write the Base64Url to</param>
    public static void Encode(Stream arg, TextWriter result)
    {
        // bytes read
        int consumed;

        // Define string holder
        Span<char> wrkBuffer = stackalloc char[4];
        Span<byte> src = stackalloc byte[3];

        // Cycle
        while (true) {
            // Get some
            consumed = arg.Read(src);

            // Check
            switch (consumed) {

                case 0:
                    // flush
                    result.Flush();

                    return;
                case 1:
                    // Encode
                    wrkBuffer[0] = _base64UrlTable[src[0] >> 2];
                    wrkBuffer[1] = _base64UrlTable[(src[0] & 0x03) << 4];

                    // Write
                    result.Write(wrkBuffer[..2]);
                    break;
                case 2:
                    // Encode
                    wrkBuffer[0] = _base64UrlTable[src[0] >> 2];
                    wrkBuffer[1] = _base64UrlTable[((src[0] & 0x03) << 4) | (src[1] >> 4)];
                    wrkBuffer[2] = _base64UrlTable[(src[1] & 0x0f) << 2];

                    // Write
                    result.Write(wrkBuffer[..3]);
                    break;
                case 3:
                    // Encode
                    wrkBuffer[0] = _base64UrlTable[src[0] >> 2];
                    wrkBuffer[1] = _base64UrlTable[((src[0] & 0x03) << 4) | (src[1] >> 4)];
                    wrkBuffer[2] = _base64UrlTable[((src[1] & 0x0f) << 2) | (src[2] >> 6)];
                    wrkBuffer[3] = _base64UrlTable[src[2] & 0x3f];

                    // Write
                    result.Write(wrkBuffer);
                    break;
                default:
                    throw new Exception("Invalid Base64Url string");
            }
        }
    }


    /// <summary>
    /// The following functions perform base64url encoding .
    /// </summary>
    /// <param name="arg">The stream to encode</param>
    /// <param name="result">The stream to write the Base64Url to</param>
    public async static Task EncodeAsync(Stream arg, TextWriter result, CancellationToken ct = default)
    {
        // bytes read
        int consumed;

        // Define string holder
        char[] wrkBuffer = new char[4];
        byte[] src = new byte[3];

        // Cycle
        while (true) {
            // Get some
            consumed = await arg.ReadAsync(src, ct);

            // Check
            switch (consumed) {

                case 0:
                    // flush
                    await result.FlushAsync();

                    return;
                case 1:
                    // Encode
                    wrkBuffer[0] = _base64UrlTable[src[0] >> 2];
                    wrkBuffer[1] = _base64UrlTable[(src[0] & 0x03) << 4];

                    // Write
                    await result.WriteAsync(wrkBuffer[..2], ct);
                    break;
                case 2:
                    // Encode
                    wrkBuffer[0] = _base64UrlTable[src[0] >> 2];
                    wrkBuffer[1] = _base64UrlTable[((src[0] & 0x03) << 4) | (src[1] >> 4)];
                    wrkBuffer[2] = _base64UrlTable[(src[1] & 0x0f) << 2];

                    // Write
                    await result.WriteAsync(wrkBuffer[..3], ct);
                    break;
                case 3:
                    // Encode
                    wrkBuffer[0] = _base64UrlTable[src[0] >> 2];
                    wrkBuffer[1] = _base64UrlTable[((src[0] & 0x03) << 4) | (src[1] >> 4)];
                    wrkBuffer[2] = _base64UrlTable[((src[1] & 0x0f) << 2) | (src[2] >> 6)];
                    wrkBuffer[3] = _base64UrlTable[src[2] & 0x3f];

                    // Write
                    await result.WriteAsync(wrkBuffer, ct);
                    break;
                default:
                    throw new Exception("Invalid Base64Url string");
            }

            // Check
            if (ct.IsCancellationRequested) {
                return;
            }
        }
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
