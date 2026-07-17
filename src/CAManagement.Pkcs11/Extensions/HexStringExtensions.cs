using System.Text;

namespace CAManagement.Pkcs11.Extensions;

public static class HexStringExtensions
{
    public static string ToHexString(this byte[] bytes) => BitConverter.ToString(bytes).Replace("-", "");

    public static string ToFormattedHexString(this byte[] bytes, bool isCode = false)
    {
        var byteString = bytes.ToHexString();
        var charsPerLine = 64;
        var lineBeginning = isCode ? "\"" : string.Empty;
        var lineEnding = isCode ? "\" +" : string.Empty;
        var sb = new StringBuilder();

        for (var i = 0; i * charsPerLine < byteString.Length; i++)
        {
            sb.AppendFormat($"{lineBeginning}{
                (byteString.Length < (i + 1) * charsPerLine
                    ? byteString.Substring(i * charsPerLine)
                    : byteString.Substring(i * charsPerLine, charsPerLine))
            }{lineEnding}\n");
        }
        
        var result = sb.ToString().TrimEnd('\n', ' ', '+');
        return result;
    }
}