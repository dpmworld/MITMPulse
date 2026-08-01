using MITMPulse.Models;

namespace MITMPulse.Services;

public interface ISslInspectionService
{
    Task<SslInspectionResult> InspectEndpointAsync(
        string targetHost,
        int targetPort,
        ProxySettings proxySettings,
        string? expectedThumbprint = null,
        EndpointPreset? preset = null,
        CancellationToken cancellationToken = default);
}
