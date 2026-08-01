namespace MITMPulse.Models;

/// <summary>
/// Persistent user configuration settings stored in %APPDATA%\dpmworld\MITMPulse\settings.json
/// </summary>
public class AppSettings
{
    public string LanguageCode { get; set; } = "auto";
    public ProxyMode SelectedProxyMode { get; set; } = ProxyMode.Direct;
    public string CustomProxyHost { get; set; } = string.Empty;
    public int CustomProxyPort { get; set; } = 8080;
}

public record LanguageOption(string Code, string DisplayName)
{
    public override string ToString() => DisplayName;
}
