namespace Nist.Vulnerability.Mirror.Http;

public class NistCveFeedClient(HttpClient client)
{
    private static async Task Download(HttpContent content, string path, CancellationToken cancellationToken)
    {
        await using Stream input = await content.ReadAsStreamAsync(cancellationToken);
        await using FileStream output = File.Create(path);

        await input.CopyToAsync(output, cancellationToken);
        await output.FlushAsync(cancellationToken);
    }

    public async Task DownloadMeta(string url, string path, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response =
            await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return;
        }

        await Download(response.Content, path, cancellationToken);
    }

    public async Task DownloadGzip(string url, string path, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response =
            await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return;
        }

        await Download(response.Content, path, cancellationToken);
    }
}
