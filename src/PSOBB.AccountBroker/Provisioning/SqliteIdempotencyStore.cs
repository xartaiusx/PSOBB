using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using PSOBB.AccountBroker.Contracts;

namespace PSOBB.AccountBroker.Provisioning;

public sealed class AccountBrokerReceiptOptions
{
    public const string SectionName = "ReceiptStore";
    public string DatabasePath { get; init; } = "../../runtime/broker/receipts.db";
    public int CompletedRetentionDays { get; init; } = 30;
}

public sealed class SqliteIdempotencyStore : IIdempotencyStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly string connectionString;

    public SqliteIdempotencyStore(IOptions<AccountBrokerReceiptOptions> options)
    {
        var value = options.Value;
        var path = Path.GetFullPath(value.DatabasePath);
        Directory.CreateDirectory(
            Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException("Receipt database path has no directory."));
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
        }.ToString();
        Initialize(value.CompletedRetentionDays);
    }

    public IdempotencyBeginResult TryBegin(Guid requestId, string requestFingerprint)
    {
        using var connection = OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT OR IGNORE INTO idempotency_receipts
                (request_id, request_fingerprint, state, response_json, created_utc, updated_utc)
            VALUES ($request_id, $fingerprint, 0, NULL, $now, $now);
            """;
        insert.Parameters.AddWithValue("$request_id", requestId.ToString("D"));
        insert.Parameters.AddWithValue("$fingerprint", requestFingerprint);
        insert.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        var inserted = insert.ExecuteNonQuery() == 1;
        if (inserted)
        {
            transaction.Commit();
            return new(IdempotencyBeginStatus.Acquired);
        }

        var row = Read(connection, transaction, requestId);
        transaction.Commit();
        if (row is null)
        {
            throw new InvalidOperationException("Receipt disappeared during acquisition.");
        }

        if (!string.Equals(row.Value.Fingerprint, requestFingerprint, StringComparison.Ordinal))
        {
            return new(IdempotencyBeginStatus.Conflict);
        }

        return row.Value.State == 0
            ? new(IdempotencyBeginStatus.InProgress)
            : row.Value.State == 2
                ? new(IdempotencyBeginStatus.OutcomeUnknown)
                : new(IdempotencyBeginStatus.Completed, Deserialize(row.Value.ResponseJson));
    }

    public IdempotencyBeginResult Lookup(Guid requestId)
    {
        using var connection = OpenConnection();
        var row = Read(connection, transaction: null, requestId);
        if (row is null)
        {
            return new(IdempotencyBeginStatus.NotFound);
        }

        return row.Value.State == 0
            ? new(IdempotencyBeginStatus.InProgress)
            : row.Value.State == 2
                ? new(IdempotencyBeginStatus.OutcomeUnknown)
                : new(IdempotencyBeginStatus.Completed, Deserialize(row.Value.ResponseJson));
    }

    public void Complete(Guid requestId, BrokerResponse responseWithoutSecret)
    {
        if (responseWithoutSecret.GamePassword is not null)
        {
            throw new ArgumentException(
                "Idempotency receipts must never retain a game password.",
                nameof(responseWithoutSecret));
        }

        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE idempotency_receipts
            SET state = 1, response_json = $response_json, updated_utc = $now
            WHERE request_id = $request_id;
            """;
        command.Parameters.AddWithValue("$response_json", JsonSerializer.Serialize(
            responseWithoutSecret, JsonOptions));
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$request_id", requestId.ToString("D"));
        if (command.ExecuteNonQuery() != 1)
        {
            throw new InvalidOperationException("The request was not acquired.");
        }
    }

    public void MarkOutcomeUnknown(Guid requestId)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE idempotency_receipts
            SET state = 2, response_json = NULL, updated_utc = $now
            WHERE request_id = $request_id;
            """;
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$request_id", requestId.ToString("D"));
        if (command.ExecuteNonQuery() != 1)
        {
            throw new InvalidOperationException("The request was not acquired.");
        }
    }

    private void Initialize(int completedRetentionDays)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            CREATE TABLE IF NOT EXISTS idempotency_receipts (
                request_id TEXT PRIMARY KEY,
                request_fingerprint TEXT NOT NULL,
                state INTEGER NOT NULL CHECK (state IN (0, 1, 2)),
                response_json TEXT NULL,
                created_utc TEXT NOT NULL,
                updated_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_idempotency_receipts_updated
                ON idempotency_receipts (updated_utc);
            """;
        command.ExecuteNonQuery();

        // Any state=0 row predates this broker process. The previous process may
        // have crashed before or after the game-side commit, so never replay it.
        using var recover = connection.CreateCommand();
        recover.CommandText = """
            UPDATE idempotency_receipts
            SET state = 2, response_json = NULL, updated_utc = $now
            WHERE state = 0;
            """;
        recover.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        recover.ExecuteNonQuery();

        using var prune = connection.CreateCommand();
        prune.CommandText = """
            DELETE FROM idempotency_receipts
            WHERE state = 1 AND updated_utc < $cutoff;
            """;
        prune.Parameters.AddWithValue(
            "$cutoff",
            DateTimeOffset.UtcNow.AddDays(-completedRetentionDays).ToString("O"));
        prune.ExecuteNonQuery();
    }

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }

    private static (string Fingerprint, int State, string? ResponseJson)? Read(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        Guid requestId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT request_fingerprint, state, response_json
            FROM idempotency_receipts
            WHERE request_id = $request_id;
            """;
        command.Parameters.AddWithValue("$request_id", requestId.ToString("D"));
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? (reader.GetString(0), reader.GetInt32(1), reader.IsDBNull(2) ? null : reader.GetString(2))
            : null;
    }

    private static BrokerResponse Deserialize(string? value) =>
        value is null
            ? throw new InvalidDataException("A completed receipt has no response.")
            : JsonSerializer.Deserialize<BrokerResponse>(value, JsonOptions)
              ?? throw new InvalidDataException("A completed receipt is invalid.");
}
