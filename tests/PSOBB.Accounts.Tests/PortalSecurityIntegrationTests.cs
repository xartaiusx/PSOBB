using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;

namespace PSOBB.Accounts.Tests;

[Collection("Portal process integration")]
public sealed class PortalSecurityIntegrationTests
{
    [Fact]
    public async Task MutatingEndpointRequiresCsrfAndReturnsGenericBoundedInputError()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "psobb-portal-http-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "portal.db");
        var previousConnection = Environment.GetEnvironmentVariable("ConnectionStrings__Portal");
        Environment.SetEnvironmentVariable("ConnectionStrings__Portal", $"Data Source={databasePath}");
        try
        {
            using var factory = new PortalFactory(databasePath);
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
                HandleCookies = true,
            });

            var withoutCsrf = await client.PostAsJsonAsync("/account/login", new
            {
                email = "nobody@example.invalid",
                password = "invalid",
            });
            Assert.Equal(HttpStatusCode.BadRequest, withoutCsrf.StatusCode);

            var csrfResponse = await client.GetAsync("/security/csrf");
            csrfResponse.EnsureSuccessStatusCode();
            var csrfCookie = Assert.Single(
                csrfResponse.Headers.GetValues("Set-Cookie"),
                value => value.StartsWith("__Host-PSOBBPortal-CSRF=", StringComparison.Ordinal));
            Assert.Contains("secure", csrfCookie, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("httponly", csrfCookie, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("samesite=strict", csrfCookie, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("path=/", csrfCookie, StringComparison.OrdinalIgnoreCase);
            using var csrfJson = JsonDocument.Parse(await csrfResponse.Content.ReadAsStringAsync());
            var token = csrfJson.RootElement.GetProperty("token").GetString();
            client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", token);

            var boundedInvalid = await client.PostAsJsonAsync("/account/login", new
            {
                email = new string('a', 255),
                password = "invalid",
            });
            Assert.Equal(HttpStatusCode.Unauthorized, boundedInvalid.StatusCode);
            Assert.Equal("no-store", boundedInvalid.Headers.CacheControl?.ToString());
            Assert.Contains(
                "invalid_credentials",
                await boundedInvalid.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ConnectionStrings__Portal", previousConnection);
            SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class PortalFactory(string databasePath) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Portal"] = $"Data Source={databasePath}",
                    ["DatabaseInitialization:Mode"] = "EnsureCreated",
                    ["Hosting:Mode"] = "DirectTls",
                    ["AllowedHosts"] = "localhost",
                }));
        }
    }
}

[CollectionDefinition("Portal process integration", DisableParallelization = true)]
public sealed class PortalProcessIntegrationCollection;
