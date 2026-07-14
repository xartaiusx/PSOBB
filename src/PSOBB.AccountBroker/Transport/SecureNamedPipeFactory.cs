using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Options;

namespace PSOBB.AccountBroker.Transport;

public sealed class SecureNamedPipeFactory(IOptions<AccountBrokerPipeOptions> options)
{
    private int createdFirstInstance;

    public NamedPipeServerStream Create()
    {
        var value = options.Value;
        var brokerSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("The broker process has no Windows SID.");
        var clientSid = new SecurityIdentifier(value.AllowedClientSid);

        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(brokerSid);
        security.AddAccessRule(new PipeAccessRule(
            brokerSid,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            clientSid,
            PipeAccessRights.ReadWrite | PipeAccessRights.ReadAttributes |
                PipeAccessRights.ReadPermissions,
            AccessControlType.Allow));

        var pipeOptions = PipeOptions.Asynchronous | PipeOptions.WriteThrough;
        if (Interlocked.Exchange(ref createdFirstInstance, 1) == 0)
        {
            pipeOptions |= PipeOptions.FirstPipeInstance;
        }

        return NamedPipeServerStreamAcl.Create(
            value.PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            pipeOptions,
            value.MaxMessageBytes,
            value.MaxMessageBytes,
            security);
    }
}
