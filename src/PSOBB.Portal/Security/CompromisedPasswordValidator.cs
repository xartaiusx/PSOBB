using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using PSOBB.Portal.Data;

namespace PSOBB.Portal.Security;

public sealed class CompromisedPasswordValidator(IConfiguration configuration)
    : IPasswordValidator<PortalUser>
{
    private static readonly HashSet<string> BuiltInDenylist = new(StringComparer.OrdinalIgnoreCase)
    {
        "password",
        "password123",
        "password123!",
        "qwerty123456789",
        "letmein123456789",
        "phantasystaronline",
    };

    public Task<IdentityResult> ValidateAsync(
        UserManager<PortalUser> manager,
        PortalUser user,
        string? password)
    {
        if (string.IsNullOrEmpty(password) || password.Length > 256 ||
            BuiltInDenylist.Contains(password))
        {
            return Task.FromResult(Rejected());
        }

        var path = configuration["Security:CompromisedPasswordDatabasePath"];
        if (!string.IsNullOrWhiteSpace(path) && IsListed(path, password))
        {
            return Task.FromResult(Rejected());
        }

        return Task.FromResult(IdentityResult.Success);
    }

    public static void ValidateDatabase(string path)
    {
        using var connection = OpenReadOnly(path);
        using var integrity = connection.CreateCommand();
        integrity.CommandText = "PRAGMA quick_check;";
        if (!string.Equals(integrity.ExecuteScalar() as string, "ok", StringComparison.Ordinal))
        {
            throw new InvalidDataException("The compromised-password database failed quick_check.");
        }

        using var schema = connection.CreateCommand();
        schema.CommandText = """
            SELECT COUNT(*)
            FROM pragma_table_info('compromised_passwords')
            WHERE name = 'sha1' AND type = 'TEXT' AND pk = 1;
            """;
        if (Convert.ToInt32(schema.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 1)
        {
            throw new InvalidDataException(
                "The compromised-password database requires compromised_passwords(sha1 TEXT PRIMARY KEY)."
            );
        }
    }

    private static bool IsListed(string path, string password)
    {
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        using var connection = OpenReadOnly(path);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT 1
            FROM compromised_passwords
            WHERE sha1 = $sha1
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$sha1", hash);
        return command.ExecuteScalar() is not null;
    }

    private static SqliteConnection OpenReadOnly(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.GetFullPath(path),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = true,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static IdentityResult Rejected() => IdentityResult.Failed(new IdentityError
    {
        Code = "CompromisedPassword",
        Description = "The password does not meet the portal security policy.",
    });
}
