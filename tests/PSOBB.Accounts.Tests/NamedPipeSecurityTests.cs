using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using PSOBB.AccountBroker.Contracts;
using PSOBB.AccountBroker.Provisioning;
using PSOBB.AccountBroker.Transport;
using PSOBB.Portal.Broker;

namespace PSOBB.Accounts.Tests;

public sealed class NamedPipeSecurityTests
{
    [Fact]
    public void FirstPipeInstancePreventsServerNameSquatting()
    {
        var pipeName = "PSOBB.Test." + Guid.NewGuid().ToString("N");
        var factory = CreateFactory(pipeName);
        using var server = factory.Create();

        var error = Record.Exception(() => new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous));
        Assert.True(
            error is IOException or UnauthorizedAccessException,
            $"Unexpected result: {error?.GetType().Name ?? "no exception"}");
    }

    [Fact]
    public async Task ClientRejectsMismatchedResponseRequestId()
    {
        var pipeName = "PSOBB.Test." + Guid.NewGuid().ToString("N");
        var factory = CreateFactory(pipeName);
        await using var server = factory.Create();
        var serverTask = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync();
            _ = await BrokerWireProtocol.ReadAsync(server, 4096, CancellationToken.None);
            var invalidResponse = JsonSerializer.SerializeToUtf8Bytes(new BrokerResponse(
                BrokerCommandHandler.ProtocolVersion,
                Guid.NewGuid(),
                BrokerResponseStatus.Succeeded));
            await BrokerWireProtocol.WriteAsync(
                server, invalidResponse, 4096, CancellationToken.None);
        });
        var client = new NamedPipeBrokerClient(
            Options.Create(new BrokerClientOptions
            {
                PipeName = pipeName,
                ConnectTimeoutMilliseconds = 2000,
                MaxResponseBytes = 4096,
            }),
            new TestHostEnvironment());
        var request = new BrokerRequest(
            BrokerCommandHandler.ProtocolVersion,
            Guid.NewGuid(),
            BrokerOperation.GetProvisioningStatus);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            client.SendAsync(request, CancellationToken.None));
        await serverTask;
    }

    [Fact]
    public async Task ClientRejectsUnexpectedPipeOwner()
    {
        var pipeName = "PSOBB.Test." + Guid.NewGuid().ToString("N");
        var factory = CreateFactory(pipeName);
        await using var server = factory.Create();
        var serverTask = server.WaitForConnectionAsync();
        var client = new NamedPipeBrokerClient(
            Options.Create(new BrokerClientOptions
            {
                PipeName = pipeName,
                ExpectedBrokerSid = "S-1-5-80-1-2-3-4-5",
                ConnectTimeoutMilliseconds = 2000,
                MaxResponseBytes = 4096,
            }),
            new TestHostEnvironment { EnvironmentName = Environments.Production });
        var request = new BrokerRequest(
            BrokerCommandHandler.ProtocolVersion,
            Guid.NewGuid(),
            BrokerOperation.GetProvisioningStatus);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            client.SendAsync(request, CancellationToken.None));
        await serverTask;
    }

    private static SecureNamedPipeFactory CreateFactory(string pipeName)
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("Test identity has no SID.");
        return new(Options.Create(new AccountBrokerPipeOptions
        {
            PipeName = pipeName,
            AllowedClientSid = sid,
            MaxMessageBytes = 4096,
            MaxConcurrentConnections = 2,
            RequestTimeoutSeconds = 5,
        }));
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "PSOBB.Accounts.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
