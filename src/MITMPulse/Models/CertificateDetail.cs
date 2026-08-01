namespace MITMPulse.Models;

/// <summary>
/// Represents structured information of an X.509 certificate.
/// </summary>
public class CertificateDetail
{
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
    public string Thumbprint { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string SignatureAlgorithm { get; set; } = string.Empty;
    public string KeyAlgorithm { get; set; } = string.Empty;
    public List<string> SubjectAlternativeNames { get; set; } = new();
    public string FormattedSan => SubjectAlternativeNames.Count > 0 ? string.Join(", ", SubjectAlternativeNames) : "None";
    public bool IsSelfSigned { get; set; }
    public bool IsExpired => DateTime.UtcNow < ValidFrom || DateTime.UtcNow > ValidTo;
}
