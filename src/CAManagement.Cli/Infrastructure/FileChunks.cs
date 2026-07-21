namespace CAManagement.Cli.Infrastructure;

/// <summary>Reads a stream as a lazy sequence of byte-array chunks (for multi-part sign/verify).</summary>
public static class FileChunks
{
    public static IEnumerable<byte[]> Read(Stream stream, int chunkSize = 64 * 1024)
    {
        var buffer = new byte[chunkSize];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            yield return buffer[..read];
        }
    }
}
