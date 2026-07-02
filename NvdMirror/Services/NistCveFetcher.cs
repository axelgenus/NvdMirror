using Microsoft.Extensions.Options;
using Nist.Vulnerability.Mirror.Http;
using Nist.Vulnerability.Mirror.Models;
using Nist.Vulnerability.Mirror.Settings;

namespace Nist.Vulnerability.Mirror.Services;

public class NistCveFetcher(
    ILogger<NistCveFetcher> logger,
    IOptions<AppSettings> options,
    TimeProvider timeProvider,
    NistCveFeedClient client) : BackgroundService
{
    private static readonly TimeSpan Warmup = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan Cooldown = TimeSpan.FromHours(2);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        const int startYear = 2002;

        await Task.Delay(Warmup, stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            DateTimeOffset now = timeProvider.GetUtcNow();

            for (int year = startYear; year < now.Year; year++)
            {
                await FetchFeed(year, stoppingToken);
            }

            await Task.Delay(Cooldown, stoppingToken);
        }
    }

    private async Task FetchFeed(int year, CancellationToken cancellationToken)
    {
        try
        {
            var metaUrl = $"nvdcve-2.0-{year}.meta";
            string metaPath = Path.Combine(options.Value.RootPath, metaUrl);

            FeedMeta? meta = await client.DownloadMeta(metaUrl, metaPath, cancellationToken);
            if (meta is null)
            {
                logger.LogWarning("Failed downloading {URL}.", metaUrl);

                return;
            }

            logger.LogInformation("Successfully downloaded {URL}", metaUrl);

            var defUrl = $"nvdcve-2.0-{year}.json.gz";
            string defPath = Path.Combine(options.Value.RootPath, defUrl);

            bool result = await client.DownloadGzip(defUrl, defPath, meta, cancellationToken);
            if (!result)
            {
                logger.LogWarning("Failed downloading {URL}.", defUrl);

                return;
            }

            logger.LogInformation("Successfully downloaded {URL}", defUrl);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Failed fetching year {YEAR}", year);
        }
    }
}