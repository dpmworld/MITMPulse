using MITMPulse.Models;

namespace MITMPulse.Services;

public interface IHistoryService
{
    Task<List<InspectionHistoryEntry>> GetHistoryAsync(CancellationToken cancellationToken = default);
    Task SaveEntryAsync(SslInspectionResult result, CancellationToken cancellationToken = default);
    Task ClearHistoryAsync(CancellationToken cancellationToken = default);
    Task ExportToJsonAsync(string filePath, CancellationToken cancellationToken = default);
    Task ExportToCsvAsync(string filePath, CancellationToken cancellationToken = default);
}
