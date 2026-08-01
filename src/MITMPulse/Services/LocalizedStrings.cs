using System.ComponentModel;
using System.Globalization;
using System.Resources;

namespace MITMPulse.Services;

/// <summary>
/// Singleton service for dynamic WPF XAML binding to localized strings from .resx files.
/// Raises PropertyChanged for all indexer properties when the active language changes.
/// </summary>
public class LocalizedStrings : INotifyPropertyChanged
{
    private static readonly ResourceManager _resourceManager =
        new ResourceManager("MITMPulse.Resources.Strings", typeof(LocalizedStrings).Assembly);

    public static LocalizedStrings Instance { get; } = new LocalizedStrings();

    public string this[string key]
    {
        get
        {
            if (string.IsNullOrWhiteSpace(key)) return string.Empty;

            try
            {
                string? localized = _resourceManager.GetString(key, CultureInfo.CurrentUICulture);
                return !string.IsNullOrEmpty(localized) ? localized : key;
            }
            catch
            {
                return key;
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public void NotifyLanguageChanged()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }
}
