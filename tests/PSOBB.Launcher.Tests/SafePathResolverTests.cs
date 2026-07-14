using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class SafePathResolverTests
{
    [TestMethod]
    public void ResolveWithinRoot_AcceptsNormalNestedPath()
    {
        using var runtime = new TestRuntime();

        var resolved = SafePathResolver.ResolveWithinRoot(runtime.Root, "client/profiles/native/psobb.exe");

        Assert.IsTrue(resolved.StartsWith(runtime.Root, StringComparison.OrdinalIgnoreCase));
        StringAssert.EndsWith(resolved, Path.Combine("client", "profiles", "native", "psobb.exe"));
    }

    [TestMethod]
    [DataRow("../outside.exe")]
    [DataRow("client/../../outside.exe")]
    [DataRow("C:/Windows/System32/cmd.exe")]
    [DataRow("\\Windows\\System32\\cmd.exe")]
    [DataRow("client/psobb.exe:payload")]
    [DataRow("client/CON.txt")]
    [DataRow("client/CON .txt")]
    [DataRow("client/file. ")]
    [DataRow("client//psobb.exe")]
    [DataRow("client/./psobb.exe")]
    public void ValidateRelativePath_RejectsUnsafeWindowsPath(string path)
    {
        Assert.ThrowsExactly<InvalidDataException>(() => SafePathResolver.ValidateRelativePath(path));
    }
}
