using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using PSOBB.AccountBroker.Contracts;
using PSOBB.AccountBroker.Provisioning;

namespace PSOBB.AccountBroker.Transport;

public sealed class AccountBrokerWorker(
    SecureNamedPipeFactory pipeFactory,
    BrokerCommandHandler handler,
    IOptions<AccountBrokerPipeOptions> options,
    ILogger<AccountBrokerWorker> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Account broker named-pipe service is ready.");
        var connectionLimit = new SemaphoreSlim(options.Value.MaxConcurrentConnections);
        var activeConnections = new List<Task>();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                activeConnections.RemoveAll(task => task.IsCompleted);
                await connectionLimit.WaitAsync(stoppingToken);
                var pipe = pipeFactory.Create();
                try
                {
                    await pipe.WaitForConnectionAsync(stoppingToken);
                }
                catch
                {
                    await pipe.DisposeAsync();
                    connectionLimit.Release();
                    throw;
                }

                activeConnections.Add(ProcessConnectionSafelyAsync(
                    pipe, connectionLimit, stoppingToken));
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal service shutdown.
        }
        finally
        {
            await Task.WhenAll(activeConnections);
            connectionLimit.Dispose();
        }
    }

    private async Task ProcessConnectionSafelyAsync(
        Stream pipe,
        SemaphoreSlim connectionLimit,
        CancellationToken stoppingToken)
    {
        await using (pipe)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken))
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(options.Value.RequestTimeoutSeconds));
            try
            {
                await ProcessConnectionAsync(pipe, deadline.Token);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning("An account-broker request exceeded its deadline.");
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                // Normal service shutdown.
            }
            catch (Exception exception)
            {
                logger.LogWarning(
                    "Rejected an invalid account-broker connection with exception type {ExceptionType}.",
                    exception.GetType().Name);
            }
            finally
            {
                connectionLimit.Release();
            }
        }
    }

    private async Task ProcessConnectionAsync(Stream pipe, CancellationToken cancellationToken)
    {
        var requestBytes = await BrokerWireProtocol.ReadAsync(
            pipe, options.Value.MaxMessageBytes, cancellationToken);
        var request = JsonSerializer.Deserialize<BrokerRequest>(requestBytes, JsonOptions)
            ?? throw new InvalidDataException("The broker request was empty.");
        var response = await handler.HandleAsync(request, cancellationToken);
        var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
        await BrokerWireProtocol.WriteAsync(
            pipe, responseBytes, options.Value.MaxMessageBytes, cancellationToken);
    }
}
