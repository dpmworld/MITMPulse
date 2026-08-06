using System.Globalization;
using System.Windows;
using MITMPulse.Services;
using MITMPulse.ViewModels;

namespace MITMPulse;

public partial class App : Application
{
    public static MainViewModel ViewModel { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Application Startup & Global Exception Handler
        // Global Unhandled Exception Handler for WPF UI Thread
        DispatcherUnhandledException += (sender, args) =>
        {
            MessageBox.Show(
                $"An unexpected UI error occurred:\n\n{args.Exception.Message}\n\nStack Trace:\n{args.Exception.StackTrace}",
                "MITMPulse Exception",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            args.Handled = true;
        };

        // Global Unhandled Exception Handler for Non-UI Threads / AppDomain
        AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
        {
            if (args.ExceptionObject is Exception ex)
            {
                MessageBox.Show(
                    $"An unhandled application error occurred:\n\n{ex.Message}\n\nStack Trace:\n{ex.StackTrace}",
                    "MITMPulse Fatal Exception",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        };

        base.OnStartup(e);

        try
        {
            var settingsService = new SettingsService();
            var settings = settingsService.LoadSettings();
            settingsService.ApplyLanguage(settings.LanguageCode);

            var proxyService = new ProxyService();
            var historyService = new HistoryService();
            var sslInspectionService = new SslInspectionService(proxyService);

            ViewModel = new MainViewModel(sslInspectionService, proxyService, historyService, settingsService, settings);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Error during application startup:\n\n{ex.Message}\n\nStack Trace:\n{ex.StackTrace}",
                "MITMPulse Startup Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }
}
