using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.ViewModels;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class MainWindowViewModelTests
{
    [TestMethod]
    public async Task Constructor_UsesPreserveForegroundSelection()
    {
        var defaults = LauncherOptions.Defaults();
        var options = defaults with
        {
            Selection = defaults.Selection with { PreserveForeground = true },
        };
        await using var viewModel = new MainWindowViewModel(options);

        Assert.IsTrue(viewModel.PreserveForeground);
    }
}
