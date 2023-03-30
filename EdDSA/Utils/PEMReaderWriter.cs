using System.Text;


namespace EdDSA.Utils;
public static class PEMReaderWriter
{
    /// <summary>
    /// Wtite PEM objects to a text writer
    /// </summary>
    /// <param name="pemObjects">PEM objects</param>
    /// <param name="sr"></param>
    /// <returns></returns>
    public static int WritePEM(IEnumerable<PEMObject> pemObjects, TextWriter textWriter)
    {
        // Create builder
        StringBuilder sb = new StringBuilder();
        foreach (var pemObject in pemObjects) {
            sb.AppendLine($"-----BEGIN {pemObject.Type}-----");
            sb.AppendLine(Convert.ToBase64String(pemObject.Content)
                                 .AsSpan()
                                 .To64LineBreak());
            sb.AppendLine($"-----END {pemObject.Type}-----");
            sb.AppendLine();
        }

        // Write it
        textWriter.Write(sb.ToString().TrimEnd(Environment.NewLine.ToCharArray()));
        textWriter.Flush();

        // Return length
        return sb.Length;
    }

    /// <summary>
    /// Read PEM objects into a memory
    /// </summary>
    /// <param name="textReader">The text reader</param>
    /// <returns>A collection of PEM</returns>
    public static ICollection<PEMObject> ReadPEM(TextReader textReader)
    {
        // locals
        ICollection<PEMObject> result = new List<PEMObject>();

        // Cycle till the end
        while (true) {
            string label;
            byte[] data;
            PEMObject pem = new PEMObject();

            // Go to the first one
            if (ReadToDash(textReader) < 0) {
                return result;
            }
            if (SkipDashes(textReader) < 0) {
                return result;
            }
            if (ReadLabel(textReader, out label) < 0) {
                return result;
            }

            // Add to result
            pem.Type = label;
            result.Add(pem);

            // Skip dashes againg
            if (SkipDashes(textReader) < 0) {
                return result;
            }

            // Read content and add to result
            if (ReadContent(textReader, out data) < 0) {
                return result;
            }
            pem.Content = data;

            // Read end line
            if (SkipDashes(textReader) < 0) {
                return result;
            }
            if (ReadLabel(textReader, out label) < 0) {
                return result;
            }
            if (SkipDashes(textReader) < 0) {
                return result;
            }
        }
    }

    private static string To64LineBreak(this ReadOnlySpan<char> src) 
    {
        StringBuilder sb = new StringBuilder();
        for (int loop = 0; loop < src.Length; loop += 64) {
            if (loop + 64 < src.Length) {
                sb.AppendLine(src[loop..(loop + 64)].ToString());
            } else {
                sb.AppendLine(src[loop..].ToString());
            }
        }
        return sb.ToString().TrimEnd(Environment.NewLine.ToCharArray());
    }

    // Move to first dash
    private static int ReadToDash(TextReader textReader)
    {
        int ch = textReader.Peek();
        while (ch != -1 && ch != '-') {
            textReader.Read();
            ch = textReader.Peek();
        }

        return ch;
    }

    private static int SkipDashes(TextReader textReader)
    {
        int ch = textReader.Peek();
        while (ch != -1 && ch == '-') {
            textReader.Read();
            ch = textReader.Peek();
        }

        return ch;
    }

    private static int ReadLabel(TextReader textReader, out string Label)
    {
        StringBuilder sb = new StringBuilder();

        int ch = textReader.Peek();
        while (ch != -1 && ch != '-') {
            sb.Append((char)textReader.Read());
            ch = textReader.Peek();
        }

        // Check 
        if (sb.Length > 0) {
            Label = sb.ToString();
            Label = Label.Replace("BEGIN", "", StringComparison.InvariantCultureIgnoreCase)
                         .Replace("END", "", StringComparison.InvariantCultureIgnoreCase)
                         .Trim()
                         .ToUpper();
        } else {
            Label = string.Empty;
        }

        return ch;
    }

    private static int ReadContent(TextReader textReader, out byte[] data)
    {
        StringBuilder sb = new StringBuilder();

        int ch = textReader.Peek();
        while (ch != -1 && ch != '-') {
            sb.Append((char)textReader.Read());
            ch = textReader.Peek();
        }

        // Check 
        if (sb.Length > 0) {
            data = Convert.FromBase64String(sb.ToString());
        } else {
            data = Array.Empty<byte>();
        }

        return ch;
    }
}

/// <summary>
/// Class to hold a basic PEM object
/// </summary>
public class PEMObject
{
    /// <summary>
    /// A lable of the PEM object
    /// </summary>
    public string Type { get; set; } = string.Empty;
    /// <summary>
    /// The content of the PEM object as bytes
    /// </summary>
    public byte[] Content { get; set; } = Array.Empty<byte>();
}
