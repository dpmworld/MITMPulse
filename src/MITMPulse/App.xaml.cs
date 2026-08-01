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
        base.OnStartup(e);

        var settingsService = new SettingsService();
        var settings = settingsService.LoadSettingsAsync().GetAwaiter().GetResult();
        settingsService.ApplyLanguage(settings.LanguageCode);

        var proxyService = new ProxyService();
        var historyService = new HistoryService();
        var sslInspectionService = new SslInspectionService(proxyService);

        ViewModel = new MainViewModel(sslInspectionService, proxyService, historyService, settingsService, settings);
    }
}
