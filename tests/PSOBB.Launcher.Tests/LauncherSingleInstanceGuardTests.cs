using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class LauncherSingleInstanceGuardTests
{
    [TestMethod]
    public void Acquire_AllowsOnlyOneOwnerAndReleasesCleanly()
    {
        var instanceName = $@"Local\PSOBB.ControlCenter.Tests.{Guid.NewGuid():N}";

        using (var first = LauncherSingleInstanceGuard.Acquire(instanceName))
        using (var second = LauncherSingleInstanceGuard.Acquire(instanceName))
        {
            Assert.IsTrue(first.IsPrimaryInstance);
            Assert.IsFalse(second.IsPrimaryInstance);
        }

        using var afterRelease = LauncherSingleInstanceGuard.Acquire(instanceName);
        Assert.IsTrue(afterRelease.IsPrimaryInstance);
    }
}
