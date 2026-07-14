using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using PSOBB.Portal.Data;
using PSOBB.Portal.Security;

namespace PSOBB.Accounts.Tests;

public sealed class InviteTokenServiceTests
{
    [Fact]
    public async Task InviteHas256BitsIsStoredHashedAndCanBeConsumedOnlyOnce()
    {
        await using var fixture = await DatabaseFixture.CreateAsync();
        var clock = new MutableTimeProvider(new DateTimeOffset(2026, 7, 13, 12, 0, 0, TimeSpan.Zero));
        var service = new InviteTokenService(fixture.Database, clock);

        var issued = await service.IssueAsync(Guid.NewGuid());
        var stored = await fixture.Database.Invites.SingleAsync();

        Assert.Equal(32, WebEncoders.Base64UrlDecode(issued.Token).Length);
        Assert.NotEqual(issued.Token, stored.TokenHash);
        Assert.Equal(64, stored.TokenHash.Length);
        Assert.Equal(clock.GetUtcNow().AddHours(24), issued.ExpiresAt);
        Assert.True(await service.ConsumeAsync(issued.Token, Guid.NewGuid()));
        Assert.False(await service.ConsumeAsync(issued.Token, Guid.NewGuid()));
    }

    [Fact]
    public async Task ExpiredInviteCannotBeConsumed()
    {
        await using var fixture = await DatabaseFixture.CreateAsync();
        var clock = new MutableTimeProvider(new DateTimeOffset(2026, 7, 13, 12, 0, 0, TimeSpan.Zero));
        var service = new InviteTokenService(fixture.Database, clock);
        var issued = await service.IssueAsync(Guid.NewGuid());

        clock.Advance(TimeSpan.FromHours(24).Add(TimeSpan.FromSeconds(1)));

        Assert.False(await service.ConsumeAsync(issued.Token, Guid.NewGuid()));
    }

    [Fact]
    public async Task ConcurrentRedemptionAcrossContextsHasOneWinner()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "psobb-invites-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "portal.db");
        try
        {
            var options = new DbContextOptionsBuilder<PortalDbContext>()
                .UseSqlite($"Data Source={path}")
                .Options;
            var clock = new MutableTimeProvider(
                new DateTimeOffset(2026, 7, 13, 12, 0, 0, TimeSpan.Zero));
            string token;
            await using (var setup = new PortalDbContext(options))
            {
                await setup.Database.EnsureCreatedAsync();
                token = (await new InviteTokenService(setup, clock)
                    .IssueAsync(Guid.NewGuid())).Token;
            }

            await using var firstDatabase = new PortalDbContext(options);
            await using var secondDatabase = new PortalDbContext(options);
            var results = await Task.WhenAll(
                new InviteTokenService(firstDatabase, clock)
                    .ConsumeAsync(token, Guid.NewGuid()),
                new InviteTokenService(secondDatabase, clock)
                    .ConsumeAsync(token, Guid.NewGuid()));

            Assert.Single(results, value => value);
            Assert.Single(results, value => !value);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset current = now;
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan duration) => current = current.Add(duration);
    }

    private sealed class DatabaseFixture : IAsyncDisposable
    {
        private DatabaseFixture(SqliteConnection connection, PortalDbContext database)
        {
            Connection = connection;
            Database = database;
        }

        private SqliteConnection Connection { get; }
        public PortalDbContext Database { get; }

        public static async Task<DatabaseFixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<PortalDbContext>()
                .UseSqlite(connection)
                .Options;
            var database = new PortalDbContext(options);
            await database.Database.EnsureCreatedAsync();
            return new(connection, database);
        }

        public async ValueTask DisposeAsync()
        {
            await Database.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }
}
