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

    public bool IsSslInspectionDetected => !IsLoading && InspectionResult != null && InspectionResult.IsSuccess && InspectionResult.IsSslInspectionDetected;
    public bool IsCertificateExpired => !IsLoading && InspectionResult != null && InspectionResult.IsSuccess && !InspectionResult.IsSslInspectionDetected && InspectionResult.ServerCertificate != null && (DateTime.UtcNow > InspectionResult.ServerCertificate.ValidTo || DateTime.UtcNow < InspectionResult.ServerCertificate.ValidFrom);
    public bool IsDirectConnection => !IsLoading && InspectionResult != null && InspectionResult.IsSuccess && !InspectionResult.IsSslInspectionDetected && !IsCertificateExpired;
    public bool IsConnectionError => !IsLoading && InspectionResult != null && !InspectionResult.IsSuccess;

    partial void OnInspectionResultChanged(SslInspectionResult? value)
    {
        OnPropertyChanged(nameof(IsSslInspectionDetected));
        OnPropertyChanged(nameof(IsCertificateExpired));
        OnPropertyChanged(nameof(IsDirectConnection));
        OnPropertyChanged(nameof(IsConnectionError));
    }

    partial void OnIsLoadingChanged(bool value)
    {
        OnPropertyChanged(nameof(IsSslInspectionDetected));
        OnPropertyChanged(nameof(IsCertificateExpired));
        OnPropertyChanged(nameof(IsDirectConnection));
        OnPropertyChanged(nameof(IsConnectionError));
    }

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
                new[] { "DigiCert", "Sectigo", "GoDaddy" },
                new DateTime(2026, 10, 16, 1, 59, 59, DateTimeKind.Utc),
                "FD93956E6143F0942FC4FD6760E65BE4FC4C8F19"),

            new EndpointPreset(
                "Citrix Workspace Agent Hub (EU)",
                "agenthub-eu.citrixworkspacesapi.net",
                443,
                "Citrix Workspace Agent Control Plane (Europe)",
                new[] { "DigiCert", "Sectigo" },
                new DateTime(2027, 1, 11, 0, 59, 59, DateTimeKind.Utc),
                "2EC3B62283D0BD480A2D5777E33CED1D88215778"),

            new EndpointPreset(
                "Citrix Workspace Agent Hub (US)",
                "agenthub-us.citrixworkspacesapi.net",
                443,
                "Citrix Workspace Agent Control Plane (United States)",
                new[] { "DigiCert", "Sectigo" },
                new DateTime(2027, 1, 11, 0, 59, 59, DateTimeKind.Utc),
                "0569B9577FE6C1C952B3B1DB48C0D9A75EB4384F"),

            new EndpointPreset(
                "Citrix Workspace Agent Hub (AP-S)",
                "agenthub-ap-s.citrixworkspacesapi.net",
                443,
                "Citrix Workspace Agent Control Plane (Asia-Pacific)",
                new[] { "DigiCert", "Sectigo" },
                new DateTime(2027, 1, 11, 0, 59, 59, DateTimeKind.Utc),
                "86892F1A8CEB820BF5D407C7C5BB91EAF30AAC1C"),

            new EndpointPreset(
                "Microsoft Entra ID / Azure AD",
                "login.microsoftonline.com",
                443,
                "Microsoft Authentication Service (High SSO SSL Inspection Risk)",
                new[] { "DigiCert", "Microsoft", "Sectigo", "GlobalSign" },
                new DateTime(2026, 12, 12, 0, 59, 59, DateTimeKind.Utc),
                "EB7711B2EA1A8D920C5060328A08A24A93C288DE"),

            new EndpointPreset(
                "Azure Virtual Desktop Gateway",
                "rdgateway.wvd.microsoft.com",
                443,
                "Microsoft Remote Desktop / AVD Gateway Service",
                new[] { "Microsoft", "DigiCert", "Sectigo" },
                new DateTime(2027, 1, 19, 17, 31, 41, DateTimeKind.Utc),
                "2F5DA3E7FA20B155C0B5E234A3152A6E4D99B6B3;B80140DC2DD174B577C81D9E30B718090CD166FC"),

            new EndpointPreset(
                "Microsoft Teams",
                "teams.microsoft.com",
                443,
                "Microsoft Teams Web & Native Client Endpoint",
                new[] { "Microsoft", "DigiCert", "Sectigo", "GlobalSign" },
                new DateTime(2026, 12, 3, 20, 36, 22, DateTimeKind.Utc),
                "2B46BCAFE6D335D2A1860048CF4481B5C6BA9F66"),

            new EndpointPreset(
                "Office 365 Exchange",
                "outlook.office365.com",
                443,
                "Microsoft Exchange Online Mail Endpoint",
                new[] { "DigiCert", "Microsoft", "Sectigo", "GlobalSign" },
                new DateTime(2027, 1, 11, 0, 59, 59, DateTimeKind.Utc),
                "C7C19E04464D744D810EF31A24C54FC22A7909C5"),

            new EndpointPreset(
                "GitHub Services",
                "github.com",
                443,
                "GitHub Repository & Git HTTPS Endpoint",
                new[] { "Sectigo", "DigiCert", "USERTrust" },
                new DateTime(2026, 10, 1, 1, 59, 59, DateTimeKind.Utc),
                "A5471F8766FEAFB2EE469970AEDA6C614D14B21B"),

            new EndpointPreset(
                "Amazon S3 API",
                "s3.amazonaws.com",
                443,
                "AWS S3 Cloud Storage API Endpoint",
                new[] { "Amazon", "Starfield", "DigiCert", "Sectigo" },
                new DateTime(2026, 11, 7, 0, 59, 59, DateTimeKind.Utc),
                "D4870314FE122746E363CC7B43A1D0D8B917AF7D"),

            new EndpointPreset(
                "Docker Hub Registry",
                "registry-1.docker.io",
                443,
                "Docker Hub Container Image Registry",
                new[] { "Amazon", "Let's Encrypt", "DigiCert", "Sectigo" },
                new DateTime(2026, 10, 24, 1, 59, 59, DateTimeKind.Utc),
                "4857230D1D1933BAD153ECD5F5B811E7F1D348A2"),

            new EndpointPreset(
                "Zoom Cloud Meetings",
                "zoom.us",
                443,
                "Zoom Video Conferencing Service",
                new[] { "DigiCert", "Sectigo", "GTS" },
                new DateTime(2026, 12, 30, 0, 59, 59, DateTimeKind.Utc),
                "43413BD950C4C81EB1C4DA67B5EB96BF4AEC7BAF"),

            new EndpointPreset(
                "Google Public Web",
                "google.com",
                443,
                "Google Public Edge Endpoint",
                new[] { "GTS", "Google", "DigiCert" },
                new DateTime(2026, 9, 21, 10, 37, 24, DateTimeKind.Utc),
                "D9DA8130783E9C6B5F9D18520EBE6D522FFB33E0"),

            new EndpointPreset(
                "Cloudflare Public Edge",
                "cloudflare.com",
                443,
                "Cloudflare Public Edge Endpoint",
                new[] { "Cloudflare", "GTS", "Google", "DigiCert", "Sectigo" },
                new DateTime(2026, 10, 7, 0, 47, 27, DateTimeKind.Utc),
                "868B692C5DED0EA40CB860DE746EEA19D0BE2E7C"),

            new EndpointPreset(
                "BadSSL Expired (Test)",
                "expired.badssl.com",
                443,
                "BadSSL Expired Certificate Test",
                new[] { "COMODO", "Comodo", "Sectigo", "Let's Encrypt", "BadSSL", "DigiCert" },
                new DateTime(2015, 4, 12, 23, 59, 59, DateTimeKind.Utc),
                "4F62A43B80E04071383A4C03B8D99215A429E57A"),

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

        if (SelectedProxyMode == ProxyMode.Custom && string.IsNullOrWhiteSpace(CustomProxyHost))
        {
            StatusMessage = "Custom Proxy mode selected: please specify Proxy Host in Settings tab.";
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
                if (InspectionResult.IsSslInspectionDetected)
                {
                    StatusMessage = "SSL INSPECTION DETECTED (MITM Proxy Active)";
                }
                else if (IsCertificateExpired)
                {
                    StatusMessage = $"CERTIFICATE EXPIRED ({InspectionResult.ServerCertificate?.ValidTo:yyyy-MM-dd}) - Direct Connection";
                }
                else
                {
                    StatusMessage = "DIRECT CONNECTION (No SSL Inspection Detected)";
                }

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
