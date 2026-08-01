using MITMPulse.Models;

namespace MITMPulse.Services;

public interface ISettingsService
{
    Task<AppSettings> LoadSettingsAsync();
    Task SaveSettingsAsync(AppSettings settings);
    void ApplyLanguage(string languageCode);
}
