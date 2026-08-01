namespace MITMPulse.Models;

/// <summary>
/// Result of an SSL/TLS inspection check.
/// </summary>
public class SslInspectionResult
{
    public string TargetHost { get; set; } = string.Empty;
    public int TargetPort { get; set; } = 443;
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public bool IsSuccess { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;
    public string TlsVersion { get; set; } = string.Empty;
    public string CipherSuite { get; set; } = string.Empty;
    public bool IsSslInspectionDetected { get; set; }
    public string InspectionReason { get; set; } = string.Empty;
    public bool IsHstsSupported { get; set; }
    public string HstsHeaderValue { get; set; } = string.Empty;
    public CertificateDetail? ServerCertificate { get; set; }
    public List<CertificateDetail> CertificateChain { get; set; } = new();
    public string PinningStatus { get; set; } = "Not Configured";
}
