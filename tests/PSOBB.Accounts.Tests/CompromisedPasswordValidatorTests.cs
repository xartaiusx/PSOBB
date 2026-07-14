using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Data.Sqlite;
using PSOBB.Portal.Data;
using PSOBB.Portal.Security;

namespace PSOBB.Accounts.Tests;

public sealed class CompromisedPasswordValidatorTests
{
    [Fact]
    public async Task BuiltInCommonPasswordIsRejected()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection().Build();
        var validator = new CompromisedPasswordValidator(configuration);

        var result = await validator.ValidateAsync(null!, new PortalUser(), "password123!");

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, error => error.Code == "CompromisedPassword");
    }

    [Fact]
    public async Task OfflineIndexedCorpusIsEnforced()
    {
        var password = "Unique-looking-but-listed!987";
        var path = Path.Combine(
            Path.GetTempPath(), "psobb-passwords-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
            await using (var connection = new SqliteConnection($"Data Source={path}"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE compromised_passwords (
                        sha1 TEXT PRIMARY KEY
                    ) WITHOUT ROWID;
                    INSERT INTO compromised_passwords (sha1) VALUES ($sha1);
                    """;
                command.Parameters.AddWithValue("$sha1", hash);
                await command.ExecuteNonQueryAsync();
            }
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Security:CompromisedPasswordDatabasePath"] = path,
                })
                .Build();
            var validator = new CompromisedPasswordValidator(configuration);

            var result = await validator.ValidateAsync(null!, new PortalUser(), password);

            Assert.False(result.Succeeded);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(path);
        }
    }
}
