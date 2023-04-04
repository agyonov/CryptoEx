using EdDSA.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EdDSA.Tests;
public class TestBase64Url
{

    private static byte[] inByteFix = { 0x3f, 0x2f, 0x1f, 0x0f, 0x3e, 0x3d, 0x3c, 0x3b, 0x3a };
    private static byte[] inByteOne = { 0x3f, 0x2f, 0x1f, 0x0f, 0x3e, 0x3d, 0x3c, 0x3b };
    private static byte[] inByteTwo = { 0x3f, 0x2f, 0x1f, 0x0f, 0x3e, 0x3d, 0x3c };

    private static string inStrFix = "Py8fDz49PDs6";
    private static string inStrOne = "Py8fDz49PDs";
    private static string inStrTwo = "Py8fDz49PA";

    [Fact(DisplayName = "Test Base64Url encode data")]
    public void Test_Base64UrlEncode()
    {
        var hh = Base64UrlEncoder.Encode(inByteFix);
        hh = Base64UrlEncoder.Encode(inByteOne);
        hh = Base64UrlEncoder.Encode(inByteTwo);
    }

    [Fact(DisplayName = "Test Base64Url decode data")]
    public void Test_Base64UrlDecode()
    {
        var hh = Base64UrlEncoder.Decode(inStrFix);
        hh = Base64UrlEncoder.Decode(inStrOne);
        hh = Base64UrlEncoder.Decode(inStrTwo);
    }
}
