using System.Windows;
using System.Diagnostics.CodeAnalysis;
using PSOBB.Launcher.ViewModels;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher;

[SuppressMessage(
    "Design",
    "CA1001:Types that own disposable fields should be disposable",
    Justification = "WPF owns the window lifetime; OnClosed asynchronously disposes the view model and its child processes.")]
public partial class MainWindow : Window
{
    private readonly MainWindowViewModel _viewModel;
    private bool _initialized;

    public MainWindow() : this(LauncherOptions.Defaults())
    {
    }

    public MainWindow(LauncherOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _viewModel = new MainWindowViewModel(options);
        InitializeComponent();
        DataContext = _viewModel;
    }

    protected override async void OnContentRendered(EventArgs e)
    {
        base.OnContentRendered(e);
        if (_initialized)
        {
            return;
        }

        _initialized = true;
        await _viewModel.InitializeAsync();
    }

    protected override async void OnClosed(EventArgs e)
    {
        await _viewModel.DisposeAsync();
        base.OnClosed(e);
    }
}
