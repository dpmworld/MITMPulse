namespace MITMPulse.Models;

/// <summary>
/// Persistent entry stored in inspection history.
/// </summary>
public class InspectionHistoryEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string TargetHost { get; set; } = string.Empty;
    public int TargetPort { get; set; } = 443;
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string TlsVersion { get; set; } = string.Empty;
    public string CipherSuite { get; set; } = string.Empty;
    public bool IsSslInspectionDetected { get; set; }
    public bool IsHstsSupported { get; set; }
    public string HstsHeaderValue { get; set; } = string.Empty;
    public bool IsSuccess { get; set; }
    public string StatusSummary { get; set; } = string.Empty;
    public string ServerIssuer { get; set; } = string.Empty;
    public string ServerThumbprint { get; set; } = string.Empty;
    public bool IsDtlsSupported { get; set; }
}
