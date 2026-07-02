using System.IO.Compression;
using System.Security.Cryptography;
using Nist.Vulnerability.Mirror.Models;

namespace Nist.Vulnerability.Mirror.Http;

public class NistCveFeedClient(HttpClient client)
{
    public async Task<FeedMeta?> DownloadMeta(string url, string path, CancellationToken cancellationToken)
    {
        FeedMeta? originalMeta = null;

        if (File.Exists(path))
        {
            string originalContents = await File.ReadAllTextAsync(path, cancellationToken);

            originalMeta = FeedMeta.Parse(originalContents);
        }

        using HttpResponseMessage response =
            await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        string updatedContents = await response.Content.ReadAsStringAsync(cancellationToken);

        FeedMeta updatedMeta = FeedMeta.Parse(updatedContents);

        if (originalMeta is null || originalMeta.LastModifiedDate < updatedMeta.LastModifiedDate)
        {
            await File.WriteAllTextAsync(path, updatedContents, cancellationToken);
        }

        return updatedMeta;
    }

    public async Task<bool> DownloadGzip(string url, string path, FeedMeta meta, CancellationToken cancellationToken)
    {
        DateTime timestamp = meta.LastModifiedDate.UtcDateTime;

        if (File.Exists(path))
        {
            var lastWriteTime = File.GetLastWriteTimeUtc(path);
            if (timestamp == lastWriteTime)
            {
                // skip download
                return true;
            }
        }

        using HttpResponseMessage response =
            await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return false;
        }

        bool valid;

        await using (Stream input = await response.Content.ReadAsStreamAsync(cancellationToken))
        await using (FileStream output = File.Create(path))
        {
            await input.CopyToAsync(output, cancellationToken);

            output.Seek(0, SeekOrigin.Begin);

            await using (var gunzip = new GZipStream(output, CompressionMode.Decompress))
            using (var sha256 = SHA256.Create())
            {
                byte[] checksum = await sha256.ComputeHashAsync(gunzip, cancellationToken);

                valid = Enumerable.SequenceEqual(meta.Sha256, checksum);
            }
        }

        if (valid)
        {
            File.SetCreationTimeUtc(path, timestamp);
            File.SetLastAccessTimeUtc(path, timestamp);
            File.SetLastWriteTimeUtc(path, timestamp);
        }

        return valid;
    }
}