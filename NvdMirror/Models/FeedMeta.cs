using System.IO.Compression;
using System.Security.Cryptography;

namespace Nist.Vulnerability.Mirror.Models;

public record FeedMeta : IComparable<FeedMeta>
{
    private const string KeyLastModifiedDate = "lastModifiedDate";
    private const string KeySize = "size";
    private const string KeyZipSize = "zipSize";
    private const string KeyGzipSize = "gzSize";
    private const string KeySha256 = "sha256";

    public DateTimeOffset LastModifiedDate { get; private set; }
    public long Size { get; private set; }
    public long ZipSize { get; private set; }
    public long GzipSize { get; private set; }
    public byte[] Sha256 { get; private set; } = [];

    public override int GetHashCode()
    {
        return Sha256.GetHashCode();
    }

    public int CompareTo(FeedMeta? other)
    {
        if (other is null) return 1;

        return LastModifiedDate.CompareTo(other.LastModifiedDate);
    }

    public virtual bool Equals(FeedMeta? other)
    {
        if (other is null) return false;

        return Enumerable.SequenceEqual(Sha256, other.Sha256);
    }

    public async Task<bool> ValidateAsync(string path, CancellationToken cancellationToken)
    {
        await using FileStream output = File.OpenRead(path);
        await using var gunzip = new GZipStream(output, CompressionMode.Decompress);

        using var sha256 = SHA256.Create();

        var hash = await sha256.ComputeHashAsync(gunzip, cancellationToken);

        return Enumerable.SequenceEqual(Sha256, hash);
    }

    public static async Task<FeedMeta?> LoadAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        string text = await File.ReadAllTextAsync(path, cancellationToken);

        return Parse(text);
    }

    public static FeedMeta? Parse(string text)
    {
        var meta = new FeedMeta();

        using var reader = new StringReader(text);

        while (reader.ReadLine() is { } line)
        {
            int index = line.IndexOf(':');
            if (index < 0) continue;

            string key = line[..index];
            string value = line[(index + 1)..];

            switch (key)
            {
                case KeyLastModifiedDate when DateTimeOffset.TryParse(value, out DateTimeOffset lastModifiedDate):
                    meta.LastModifiedDate = lastModifiedDate;
                    break;

                case KeySize when long.TryParse(value, out long size):
                    meta.Size = size;
                    break;

                case KeyZipSize when long.TryParse(value, out long size):
                    meta.ZipSize = size;
                    break;

                case KeyGzipSize when long.TryParse(value, out long size):
                    meta.GzipSize = size;
                    break;

                case KeySha256:
                    meta.Sha256 = Convert.FromHexString(value);
                    break;

                default: throw new NotSupportedException($"Invalid metadata field {key}");
            }
        }

        return meta;
    }
}
