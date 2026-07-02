using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Nist.Vulnerability.Mirror.Http;
using Nist.Vulnerability.Mirror.Services;
using Nist.Vulnerability.Mirror.Settings;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

string? rootPath = builder.Configuration["RootPath"] ?? Path.GetTempPath();

builder.Services.Configure<AppSettings>(settings =>
{
    settings.RootPath = rootPath;
});

builder.Services.AddSingleton(TimeProvider.System);

builder.Services.AddHttpClient<NistCveFeedClient>(client =>
{
    client.BaseAddress = new Uri("https://nvd.nist.gov/feeds/json/cve/2.0/");
});

builder.Services.AddHostedService<NistCveFetcher>();

WebApplication app = builder.Build();

var contentTypeProvider = new FileExtensionContentTypeProvider
{
    Mappings =
    {
        [".meta"] = "text/plain",
        [".gz"] = "application/gzip"
    }
};

var fileProvider = new PhysicalFileProvider(rootPath);

var staticFileOptions = new StaticFileOptions
{
    ContentTypeProvider = contentTypeProvider,
    FileProvider = fileProvider,
    RequestPath = PathString.Empty, // Serve at the root of the domain
};

app.UseStaticFiles(staticFileOptions);

app.MapFallback(() => Results.NotFound());

app.Run();