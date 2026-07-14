using System.Windows;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher;

public partial class App : Application
{
    private LauncherSingleInstanceGuard? _controlCenterInstance;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        try
        {
            var options = LauncherCommandLine.Parse(e.Args);
            if (options.Operation == LauncherOperation.Gui)
            {
                _controlCenterInstance = LauncherSingleInstanceGuard.AcquireControlCenter();
                if (!_controlCenterInstance.IsPrimaryInstance)
                {
                    MessageBox.Show(
                        "PSOBB Control Center is already open in this Windows session.",
                        "PSOBB Control Center",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    Shutdown(0);
                    return;
                }

                var window = new MainWindow(options);
                MainWindow = window;
                ShutdownMode = ShutdownMode.OnMainWindowClose;
                window.Show();
                return;
            }

            await using var coordinator = LauncherServices.CreateCoordinator();
            var snapshot = await new LauncherCommandHost(coordinator).ExecuteAsync(options);
            if (snapshot.State == LauncherLifecycleState.Faulted)
            {
                throw new InvalidOperationException(snapshot.Detail);
            }

            Shutdown(0);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            MessageBox.Show(
                exception.Message,
                "PSOBB Launcher",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _controlCenterInstance?.Dispose();
        _controlCenterInstance = null;
        base.OnExit(e);
    }
}
