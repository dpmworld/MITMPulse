using System.IO;
using System.Text;
using System.Text.Json;
using MITMPulse.Models;

namespace MITMPulse.Services;

public class HistoryService : IHistoryService
{
    private readonly string _historyFilePath;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public HistoryService()
    {
        string appDataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "dpmworld",
            "MITMPulse");

        Directory.CreateDirectory(appDataDir);
        _historyFilePath = Path.Combine(appDataDir, "history.json");
    }

    public HistoryService(string customFilePath)
    {
        _historyFilePath = customFilePath;
        string? dir = Path.GetDirectoryName(customFilePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
    }

    public async Task<List<InspectionHistoryEntry>> GetHistoryAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_historyFilePath))
        {
            return new List<InspectionHistoryEntry>();
        }

        try
        {
            using FileStream stream = File.OpenRead(_historyFilePath);
            var list = await JsonSerializer.DeserializeAsync<List<InspectionHistoryEntry>>(stream, JsonOptions, cancellationToken);
            return list ?? new List<InspectionHistoryEntry>();
        }
        catch
        {
            return new List<InspectionHistoryEntry>();
        }
    }

    public async Task SaveEntryAsync(SslInspectionResult result, CancellationToken cancellationToken = default)
    {
        var history = await GetHistoryAsync(cancellationToken);

        string statusSummary = result.IsSuccess
            ? (result.IsSslInspectionDetected ? "SSL Inspection Detected" : "Direct Connection")
            : $"Error: {result.ErrorMessage}";

        var entry = new InspectionHistoryEntry
        {
            TargetHost = result.TargetHost,
            TargetPort = result.TargetPort,
            Timestamp = result.Timestamp,
            TlsVersion = result.TlsVersion,
            CipherSuite = result.CipherSuite,
            IsSslInspectionDetected = result.IsSslInspectionDetected,
            IsHstsSupported = result.IsHstsSupported,
            HstsHeaderValue = result.HstsHeaderValue,
            IsSuccess = result.IsSuccess,
            StatusSummary = statusSummary,
            ServerIssuer = result.ServerCertificate?.Issuer ?? string.Empty,
            ServerThumbprint = result.ServerCertificate?.Thumbprint ?? string.Empty,
            IsDtlsSupported = result.IsDtlsSupported
        };

        history.Insert(0, entry); // Add newest at top

        // Keep last 200 entries
        if (history.Count > 200)
        {
            history = history.Take(200).ToList();
        }

        await using FileStream stream = File.Create(_historyFilePath);
        await JsonSerializer.SerializeAsync(stream, history, JsonOptions, cancellationToken);
    }

    public Task ClearHistoryAsync(CancellationToken cancellationToken = default)
    {
        if (File.Exists(_historyFilePath))
        {
            File.Delete(_historyFilePath);
        }
        return Task.CompletedTask;
    }

    public async Task ExportToJsonAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var history = await GetHistoryAsync(cancellationToken);
        await using FileStream stream = File.Create(filePath);
        await JsonSerializer.SerializeAsync(stream, history, JsonOptions, cancellationToken);
    }

    public async Task ExportToCsvAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var history = await GetHistoryAsync(cancellationToken);
        var sb = new StringBuilder();
        sb.AppendLine("Timestamp,TargetHost,TargetPort,IsSuccess,IsSslInspectionDetected,IsDtlsSupported,TlsVersion,CipherSuite,ServerIssuer,ServerThumbprint,StatusSummary");

        foreach (var item in history)
        {
            sb.AppendLine($"\"{item.Timestamp:yyyy-MM-dd HH:mm:ss}\",\"{EscapeCsv(item.TargetHost)}\",{item.TargetPort},{item.IsSuccess},{item.IsSslInspectionDetected},{item.IsDtlsSupported},\"{EscapeCsv(item.TlsVersion)}\",\"{EscapeCsv(item.CipherSuite)}\",\"{EscapeCsv(item.ServerIssuer)}\",\"{EscapeCsv(item.ServerThumbprint)}\",\"{EscapeCsv(item.StatusSummary)}\"");
        }

        await File.WriteAllTextAsync(filePath, sb.ToString(), Encoding.UTF8, cancellationToken);
    }

    private static string EscapeCsv(string input)
    {
        string escaped = input.Replace("\"", "\"\"");

        // Prevent CSV/formula injection: neutralize values that Excel/LibreOffice
        // may interpret as formulas (e.g. a malicious certificate Issuer field).
        if (escaped.Length > 0 && (escaped[0] == '=' || escaped[0] == '+' || escaped[0] == '-' || escaped[0] == '@' || escaped[0] == '\t' || escaped[0] == '\r'))
        {
            escaped = "'" + escaped;
        }

        return escaped;
    }
}
