namespace Nist.Vulnerability.Mirror.Models;

public record FeedMeta(DateTimeOffset LastModifiedDate, long Size, long ZipSize, long GzipSize, byte[] Sha256)
{
    public static FeedMeta Parse(string text)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        using var reader = new StringReader(text);

        while (reader.ReadLine() is { } line)
        {
            int index = line.IndexOf(':');
            if (index < 0) continue;

            dict[line[..index]] = line[(index + 1)..];
        }

        return new FeedMeta(
            LastModifiedDate: DateTimeOffset.Parse(dict["lastModifiedDate"]),
            Size: long.Parse(dict["size"]),
            ZipSize: long.Parse(dict["zipSize"]),
            GzipSize: long.Parse(dict["gzSize"]),
            Sha256: Convert.FromHexString(dict["sha256"])
        );
    }
}