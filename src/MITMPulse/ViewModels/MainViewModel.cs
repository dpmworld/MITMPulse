using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MITMPulse.Models;
using MITMPulse.Services;

namespace MITMPulse.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly ISslInspectionService _sslInspectionService;
    private readonly IProxyService _proxyService;
    private readonly IHistoryService _historyService;
    private readonly ISettingsService? _settingsService;

    public string AppTitleWithVersion
    {
        get
        {
            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            string verStr = version != null ? $"v{version.Major}.{version.Minor}.{version.Build}" : "v1.0.0";
            return $"MITMPulse {verStr}";
        }
    }

    [ObservableProperty]
    private ObservableCollection<LanguageOption> _availableLanguages = new();

    [ObservableProperty]
    private LanguageOption? _selectedLanguage;

    [ObservableProperty]
    private ObservableCollection<EndpointPreset> _presets = new();

    [ObservableProperty]
    private EndpointPreset? _selectedPreset;

    [ObservableProperty]
    private string _targetInput = "global-all.g.nssvc.net:443";

    [ObservableProperty]
    private string _expectedThumbprint = string.Empty;

    [ObservableProperty]
    private ProxyMode _selectedProxyMode = ProxyMode.Direct;

    [ObservableProperty]
    private string _customProxyHost = string.Empty;

    [ObservableProperty]
    private int _customProxyPort = 8080;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    [ObservableProperty]
    private SslInspectionResult? _inspectionResult;

    [ObservableProperty]
    private ObservableCollection<InspectionHistoryEntry> _history = new();

    public MainViewModel(
        ISslInspectionService sslInspectionService,
        IProxyService proxyService,
        IHistoryService historyService,
        ISettingsService? settingsService = null,
        AppSettings? initialSettings = null)
    {
        _sslInspectionService = sslInspectionService;
        _proxyService = proxyService;
        _historyService = historyService;
        _settingsService = settingsService;

        InitializeLanguages(initialSettings?.LanguageCode ?? "auto");

        if (initialSettings != null)
        {
            SelectedProxyMode = initialSettings.SelectedProxyMode;
            CustomProxyHost = initialSettings.CustomProxyHost;
            CustomProxyPort = initialSettings.CustomProxyPort;
        }

        InitializePresets();
        _ = LoadHistoryAsync();
    }

    private void InitializeLanguages(string initialCode)
    {
        AvailableLanguages = new ObservableCollection<LanguageOption>
        {
            new LanguageOption("auto", "Auto (System Language)"),
            new LanguageOption("en", "English (en-US)"),
            new LanguageOption("it", "Italiano (it-IT)"),
            new LanguageOption("fr", "Français (fr-FR)")
        };

        SelectedLanguage = AvailableLanguages.FirstOrDefault(l => l.Code.Equals(initialCode, StringComparison.OrdinalIgnoreCase))
                           ?? AvailableLanguages.First();
    }

    partial void OnSelectedLanguageChanged(LanguageOption? value)
    {
        if (value != null && _settingsService != null)
        {
            _settingsService.ApplyLanguage(value.Code);
            _ = SaveSettingsAsync();
        }
    }

    private void InitializePresets()
    {
        Presets = new ObservableCollection<EndpointPreset>
        {
            new EndpointPreset(
                "NetScaler Gateway Service",
                "global-all.g.nssvc.net",
                443,
                "Citrix NetScaler Gateway Service Endpoint (DaaS)",
                new[] { "DigiCert" },
                new DateTime(2026, 11, 15)),

            new EndpointPreset(
                "Citrix Portal",
                "citrix.com",
                443,
                "Citrix Official Web Portal",
                new[] { "DigiCert" }),

            new EndpointPreset(
                "Microsoft Entra ID / Azure AD",
                "login.microsoftonline.com",
                443,
                "Microsoft Authentication Service (High SSO SSL Inspection Risk)",
                new[] { "DigiCert", "Microsoft" }),

            new EndpointPreset(
                "Microsoft Teams",
                "teams.microsoft.com",
                443,
                "Microsoft Teams Web & Native Client Endpoint",
                new[] { "DigiCert", "Microsoft" }),

            new EndpointPreset(
                "Office 365 Exchange",
                "outlook.office365.com",
                443,
                "Microsoft Exchange Online Mail Endpoint",
                new[] { "DigiCert", "Microsoft" }),

            new EndpointPreset(
                "GitHub Services",
                "github.com",
                443,
                "GitHub Repository & Git HTTPS Endpoint",
                new[] { "DigiCert" }),

            new EndpointPreset(
                "Amazon S3 API",
                "s3.amazonaws.com",
                443,
                "AWS S3 Cloud Storage API Endpoint",
                new[] { "Amazon", "Starfield", "DigiCert" }),

            new EndpointPreset(
                "Docker Hub Registry",
                "registry-1.docker.io",
                443,
                "Docker Hub Container Image Registry",
                new[] { "Amazon", "Let's Encrypt", "DigiCert" }),

            new EndpointPreset(
                "Zoom Cloud Meetings",
                "zoom.us",
                443,
                "Zoom Video Conferencing Service",
                new[] { "DigiCert" }),

            new EndpointPreset(
                "Google Public Web",
                "google.com",
                443,
                "Google Public Edge Endpoint",
                new[] { "GTS", "Google Trust" },
                new DateTime(2026, 12, 31)),

            new EndpointPreset(
                "Cloudflare Public Edge",
                "cloudflare.com",
                443,
                "Cloudflare Public Edge Endpoint",
                new[] { "Cloudflare", "DigiCert", "Sectigo" },
                new DateTime(2026, 12, 31)),

            new EndpointPreset(
                "BadSSL Expired (Test)",
                "expired.badssl.com",
                443,
                "BadSSL Expired Certificate Test",
                new[] { "BadSSL", "Let's Encrypt" }),

            new EndpointPreset(
                "BadSSL Self-Signed (Test)",
                "self-signed.badssl.com",
                443,
                "BadSSL Self-Signed Certificate Test",
                new[] { "BadSSL" }),

            new EndpointPreset(
                "BadSSL Untrusted Root (Test)",
                "untrusted-root.badssl.com",
                443,
                "BadSSL Untrusted Root Test",
                new[] { "BadSSL" })
        };

        SelectedPreset = Presets.First();
    }

    partial void OnSelectedPresetChanged(EndpointPreset? value)
    {
        if (value != null)
        {
            TargetInput = value.FullAddress;
        }
    }

    [RelayCommand]
    public async Task InspectEndpointAsync()
    {
        if (string.IsNullOrWhiteSpace(TargetInput))
        {
            StatusMessage = "Please specify a target endpoint.";
            return;
        }

        IsLoading = true;
        StatusMessage = "Connecting and inspecting SSL/TLS endpoint...";
        InspectionResult = null;

        string input = TargetInput.Trim();
        if (input.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            input = input.Substring(8);
        }
        else if (input.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            input = input.Substring(7);
        }

        int slashIndex = input.IndexOf('/');
        if (slashIndex >= 0)
        {
            input = input.Substring(0, slashIndex);
        }

        string host = input;
        int port = 443; // Default to port 443 if omitted

        if (host.Contains(':'))
        {
            var parts = host.Split(':');
            host = parts[0];
            if (parts.Length > 1 && int.TryParse(parts[1], out int parsedPort))
            {
                port = parsedPort;
            }
        }

        var proxySettings = new ProxySettings
        {
            Mode = SelectedProxyMode,
            Host = CustomProxyHost,
            Port = CustomProxyPort
        };

        try
        {
            var currentPreset = Presets.FirstOrDefault(p => p.Host.Equals(host, StringComparison.OrdinalIgnoreCase)) ?? SelectedPreset;

            InspectionResult = await _sslInspectionService.InspectEndpointAsync(
                host,
                port,
                proxySettings,
                ExpectedThumbprint,
                currentPreset);

            if (InspectionResult.IsSuccess)
            {
                StatusMessage = InspectionResult.IsSslInspectionDetected
                    ? "SSL INSPECTION DETECTED (MITM Proxy Active)"
                    : "DIRECT CONNECTION (No SSL Inspection Detected)";

                await _historyService.SaveEntryAsync(InspectionResult);
                await LoadHistoryAsync();
            }
            else
            {
                StatusMessage = $"Connection failed: {InspectionResult.ErrorMessage}";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task LoadHistoryAsync()
    {
        var entries = await _historyService.GetHistoryAsync();
        History = new ObservableCollection<InspectionHistoryEntry>(entries);
    }

    [RelayCommand]
    public async Task ClearHistoryAsync()
    {
        await _historyService.ClearHistoryAsync();
        History.Clear();
        StatusMessage = "History cleared.";
    }

    [RelayCommand]
    public async Task ExportJsonAsync(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return;
        await _historyService.ExportToJsonAsync(filePath);
        StatusMessage = $"Exported history to JSON: {filePath}";
    }

    [RelayCommand]
    public async Task ExportCsvAsync(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return;
        await _historyService.ExportToCsvAsync(filePath);
        StatusMessage = $"Exported history to CSV: {filePath}";
    }

    partial void OnSelectedProxyModeChanged(ProxyMode value) => _ = SaveSettingsAsync();
    partial void OnCustomProxyHostChanged(string value) => _ = SaveSettingsAsync();
    partial void OnCustomProxyPortChanged(int value) => _ = SaveSettingsAsync();

    private async Task SaveSettingsAsync()
    {
        if (_settingsService != null)
        {
            var settings = new AppSettings
            {
                LanguageCode = SelectedLanguage?.Code ?? "auto",
                SelectedProxyMode = SelectedProxyMode,
                CustomProxyHost = CustomProxyHost,
                CustomProxyPort = CustomProxyPort
            };
            await _settingsService.SaveSettingsAsync(settings);
        }
    }
}
