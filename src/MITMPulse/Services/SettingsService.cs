using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Markup;
using MITMPulse.Models;

namespace MITMPulse.Services;

public class SettingsService : ISettingsService
{
    private readonly string _settingsFilePath;

    public SettingsService()
    {
        string appDataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "dpmworld",
            "MITMPulse");

        Directory.CreateDirectory(appDataDir);
        _settingsFilePath = Path.Combine(appDataDir, "settings.json");
    }

    public async Task<AppSettings> LoadSettingsAsync()
    {
        if (!File.Exists(_settingsFilePath))
        {
            return new AppSettings();
        }

        try
        {
            string json = await File.ReadAllTextAsync(_settingsFilePath);
            var settings = JsonSerializer.Deserialize<AppSettings>(json);
            return settings ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public async Task SaveSettingsAsync(AppSettings settings)
    {
        try
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(settings, options);
            await File.ReadAllTextAsync(_settingsFilePath);
            await File.WriteAllTextAsync(_settingsFilePath, json);
        }
        catch
        {
            // Ignore write errors
        }
    }

    public void ApplyLanguage(string languageCode)
    {
        CultureInfo culture = languageCode.ToLowerInvariant() switch
        {
            "it" => new CultureInfo("it-IT"),
            "fr" => new CultureInfo("fr-FR"),
            "en" => new CultureInfo("en-US"),
            _ => CultureInfo.CurrentCulture // Auto / System language
        };

        CultureInfo.DefaultThreadCurrentCulture = culture;
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        Thread.CurrentThread.CurrentCulture = culture;
        Thread.CurrentThread.CurrentUICulture = culture;
        CultureInfo.CurrentCulture = culture;
        CultureInfo.CurrentUICulture = culture;

        LocalizedStrings.Instance.NotifyLanguageChanged();

        // Apply XmlLanguage to WPF Framework Elements if Application.Current is available
        if (Application.Current != null)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                foreach (Window window in Application.Current.Windows)
                {
                    window.Language = XmlLanguage.GetLanguage(culture.IetfLanguageTag);
                }
            });
        }
    }
}
