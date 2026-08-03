using MITMPulse.Models;

namespace MITMPulse.Services;

public interface ISettingsService
{
    AppSettings LoadSettings();
    Task<AppSettings> LoadSettingsAsync();
    void SaveSettings(AppSettings settings);
    Task SaveSettingsAsync(AppSettings settings);
    void ApplyLanguage(string languageCode);
}
