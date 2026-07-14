using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace PSOBB.Portal.Data;

public sealed class PortalDatabaseInitializer(
    IServiceProvider services,
    IConfiguration configuration,
    IHostEnvironment environment) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var connectionString = configuration.GetConnectionString("Portal")
            ?? throw new InvalidOperationException("ConnectionStrings:Portal is required.");
        var dataSource = new SqliteConnectionStringBuilder(connectionString).DataSource;
        if (!string.IsNullOrWhiteSpace(dataSource) && dataSource != ":memory:")
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(dataSource));
            if (directory is not null)
            {
                Directory.CreateDirectory(directory);
            }
        }

        await using var scope = services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        var mode = configuration["DatabaseInitialization:Mode"] ?? "EnsureCreated";
        if (string.Equals(mode, "EnsureCreated", StringComparison.OrdinalIgnoreCase))
        {
            if (environment.IsProduction())
            {
                throw new InvalidOperationException(
                    "EnsureCreated is forbidden in Production; use reviewed EF migrations.");
            }

            await database.Database.EnsureCreatedAsync(cancellationToken);
            return;
        }

        if (!string.Equals(mode, "Migrate", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("DatabaseInitialization:Mode is invalid.");
        }

        if (!database.Database.GetMigrations().Any())
        {
            throw new InvalidOperationException(
                "Production database migration gate failed: no reviewed migrations exist.");
        }

        await database.Database.MigrateAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
