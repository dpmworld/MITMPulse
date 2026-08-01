using System.IO;
using MITMPulse.Models;
using MITMPulse.Services;
using Xunit;

namespace MITMPulse.Tests.Services;

public class HistoryServiceTests : IDisposable
{
    private readonly string _tempFilePath;
    private readonly HistoryService _sut;

    public HistoryServiceTests()
    {
        _tempFilePath = Path.Combine(Path.GetTempPath(), $"test_history_{Guid.NewGuid()}.json");
        _sut = new HistoryService(_tempFilePath);
    }

    public void Dispose()
    {
        if (File.Exists(_tempFilePath))
        {
            File.Delete(_tempFilePath);
        }
    }

    [Fact]
    public async Task SaveEntryAsync_ValidResult_WritesEntryToHistory()
    {
        // Arrange
        var result = new SslInspectionResult
        {
            TargetHost = "global-all.g.nssvc.net",
            TargetPort = 443,
            IsSuccess = true,
            TlsVersion = "Tls13",
            CipherSuite = "TLS_AES_256_GCM_SHA384",
            IsSslInspectionDetected = false,
            ServerCertificate = new CertificateDetail
            {
                Issuer = "DigiCert Global Root CA",
                Thumbprint = "ABCDEF1234567890"
            }
        };

        // Act
        await _sut.SaveEntryAsync(result);
        var history = await _sut.GetHistoryAsync();

        // Assert
        Assert.Single(history);
        Assert.Equal("global-all.g.nssvc.net", history[0].TargetHost);
        Assert.Equal(443, history[0].TargetPort);
        Assert.Equal("Tls13", history[0].TlsVersion);
        Assert.False(history[0].IsSslInspectionDetected);
    }

    [Fact]
    public async Task ClearHistoryAsync_RemovesFileAndEntries()
    {
        // Arrange
        var result = new SslInspectionResult { TargetHost = "example.com", TargetPort = 443, IsSuccess = true };
        await _sut.SaveEntryAsync(result);

        // Act
        await _sut.ClearHistoryAsync();
        var history = await _sut.GetHistoryAsync();

        // Assert
        Assert.Empty(history);
    }

    [Fact]
    public async Task ExportToCsvAsync_ValidHistory_CreatesCsvFile()
    {
        // Arrange
        var result = new SslInspectionResult { TargetHost = "example.com", TargetPort = 443, IsSuccess = true };
        await _sut.SaveEntryAsync(result);

        string csvPath = Path.Combine(Path.GetTempPath(), $"export_{Guid.NewGuid()}.csv");

        try
        {
            // Act
            await _sut.ExportToCsvAsync(csvPath);

            // Assert
            Assert.True(File.Exists(csvPath));
            string content = await File.ReadAllTextAsync(csvPath);
            Assert.Contains("example.com", content);
        }
        finally
        {
            if (File.Exists(csvPath)) File.Delete(csvPath);
        }
    }
}
