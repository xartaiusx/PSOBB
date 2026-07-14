using System.Windows;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class WpfBindingTests
{
    [STATestMethod]
    public void MainWindowCanReachLoadedState()
    {
        var application = Application.Current ?? new Application();
        var window = new MainWindow
        {
            ShowActivated = false,
            ShowInTaskbar = false,
            WindowState = WindowState.Minimized,
        };

        try
        {
            window.Show();
            window.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Loaded);
            Assert.IsTrue(window.IsLoaded);
        }
        finally
        {
            window.Close();
            if (ReferenceEquals(Application.Current, application))
            {
                application.Shutdown();
            }
        }
    }
}
