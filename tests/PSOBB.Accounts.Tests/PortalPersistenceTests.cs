using PSOBB.Portal.Data;

namespace PSOBB.Accounts.Tests;

public sealed class PortalPersistenceTests
{
    [Fact]
    public void PortalEntitiesHaveNoGamePasswordProperty()
    {
        var entityTypes = new[]
        {
            typeof(PortalUser),
            typeof(Invite),
            typeof(GameAccountLink),
            typeof(ProvisioningRequest),
            typeof(AuditEvent),
        };

        Assert.All(entityTypes, type =>
            Assert.DoesNotContain(type.GetProperties(), property =>
                property.Name.Contains("GamePassword", StringComparison.OrdinalIgnoreCase)));
    }
}
