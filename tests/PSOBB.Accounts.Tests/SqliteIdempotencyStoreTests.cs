using Microsoft.Extensions.Options;
using PSOBB.AccountBroker.Contracts;
using PSOBB.AccountBroker.Provisioning;

namespace PSOBB.Accounts.Tests;

public sealed class SqliteIdempotencyStoreTests
{
    [Fact]
    public void ReceiptAndFingerprintSurviveStoreRestart()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "psobb-receipts-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "receipts.db");
        try
        {
            var options = Options.Create(new AccountBrokerReceiptOptions
            {
                DatabasePath = path,
                CompletedRetentionDays = 30,
            });
            var requestId = Guid.NewGuid();
            var firstStore = new SqliteIdempotencyStore(options);
            Assert.Equal(
                IdempotencyBeginStatus.Acquired,
                firstStore.TryBegin(requestId, "fingerprint-a").Status);
            firstStore.Complete(requestId, new(
                1,
                requestId,
                BrokerResponseStatus.Succeeded,
                GameAccountId: "1001",
                GameUsername: "player01"));

            var restartedStore = new SqliteIdempotencyStore(options);
            var replay = restartedStore.TryBegin(requestId, "fingerprint-a");
            var conflict = restartedStore.TryBegin(requestId, "fingerprint-b");

            Assert.Equal(IdempotencyBeginStatus.Completed, replay.Status);
            Assert.Equal(BrokerResponseStatus.Succeeded, replay.CompletedResponse!.Status);
            Assert.Null(replay.CompletedResponse.GamePassword);
            Assert.Equal(IdempotencyBeginStatus.Conflict, conflict.Status);

            var interruptedRequestId = Guid.NewGuid();
            Assert.Equal(
                IdempotencyBeginStatus.Acquired,
                restartedStore.TryBegin(interruptedRequestId, "fingerprint-c").Status);
            var afterCrash = new SqliteIdempotencyStore(options);
            Assert.Equal(
                IdempotencyBeginStatus.OutcomeUnknown,
                afterCrash.TryBegin(interruptedRequestId, "fingerprint-c").Status);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
