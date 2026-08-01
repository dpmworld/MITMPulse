namespace MITMPulse.Models;

public enum ProxyMode
{
    Direct,
    System,
    Custom
}

/// <summary>
/// Model for proxy configuration settings.
/// </summary>
public class ProxySettings
{
    public ProxyMode Mode { get; set; } = ProxyMode.Direct;
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 8080;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
