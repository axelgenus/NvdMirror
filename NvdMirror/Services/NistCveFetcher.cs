using Microsoft.Extensions.Options;
using Nist.Vulnerability.Mirror.Http;
using Nist.Vulnerability.Mirror.Models;
using Nist.Vulnerability.Mirror.Settings;

namespace Nist.Vulnerability.Mirror.Services;

public partial class NistCveFetcher(
    ILogger<NistCveFetcher> logger,
    IOptions<AppSettings> options,
    TimeProvider timeProvider,
    NistCveFeedClient client) : BackgroundService
{
    private const int StartYear = 2002;

    private static readonly TimeSpan UpdatePeriod = TimeSpan.FromHours(2);

    private readonly PeriodicTimer _timer = new(UpdatePeriod, timeProvider);

    [LoggerMessage(LogLevel.Information, "Failed downloading metadata (feed {name}).")]
    private partial void LogFailedDownloadingMeta(string name);

    [LoggerMessage(LogLevel.Information, "No changes detected (feed {name}).")]
    private partial void LogNoChangesDetected(string name);

    [LoggerMessage(LogLevel.Warning, "Failed definitions validation  (feed {name}).")]
    private partial void LogFailedDefinitionsValidation(string name);

    private async Task FetchFeed(string name, CancellationToken cancellationToken)
    {
        var metaUrl = $"nvdcve-2.0-{name}.meta";
        string metaPath = Path.Combine(options.Value.RootPath, metaUrl);

        var defUrl = $"nvdcve-2.0-{name}.json.gz";
        string defPath = Path.Combine(options.Value.RootPath, defUrl);

        try
        {
            FeedMeta? existingMeta = await FeedMeta.LoadAsync(metaPath, cancellationToken);

            await client.DownloadMeta(metaUrl, metaPath, cancellationToken);

            FeedMeta? updatedMeta = await FeedMeta.LoadAsync(metaPath, cancellationToken);
            if (updatedMeta is null)
            {
                LogFailedDownloadingMeta(name);

                return;
            }

            if (existingMeta is not null && existingMeta.CompareTo(updatedMeta) <= 0)
            {
                LogNoChangesDetected(name);

                return;
            }

            await client.DownloadGzip(defUrl, defPath, cancellationToken);

            if (!await updatedMeta.ValidateAsync(defPath, cancellationToken))
            {
                LogFailedDefinitionsValidation(name);

                //File.Delete(defPath);
            }
        }
        catch (TaskCanceledException)
        {
            logger.LogWarning("Fetching feed {name} has been cancelled.", name);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Failed fetching year {name}", name);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (await _timer.WaitForNextTickAsync(stoppingToken))
        {
            DateTimeOffset now = timeProvider.GetUtcNow();

            for (int year = StartYear; year <= now.Year; year++)
            {
                await FetchFeed($"{year}", stoppingToken);
            }

            await FetchFeed("modified", stoppingToken);

            await Task.Delay(UpdatePeriod, stoppingToken);
        }
    }
}