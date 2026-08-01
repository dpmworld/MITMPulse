namespace MITMPulse.Models;

/// <summary>
/// Represents a predefined target endpoint preset for quick selection in the UI.
/// Includes baseline expectations (expected public issuers, known expiration date).
/// </summary>
public record EndpointPreset(
    string DisplayName,
    string Host,
    int Port,
    string Description,
    string[] ExpectedPublicIssuers,
    DateTime? KnownCertExpirationDate = null,
    string? KnownThumbprint = null)
{
    public string FullAddress => $"{Host}:{Port}";

    public override string ToString() => $"{DisplayName} ({FullAddress})";
}
