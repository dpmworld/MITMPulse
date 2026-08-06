using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using MITMPulse.Models;
using MITMPulse.Services;
using MITMPulse.ViewModels;
using Xunit;

namespace MITMPulse.Tests.Services;

public class PresetVerificationTests
{
    [Fact]
    public async Task Presets_VerifyOnlineThumbprintsAndExpirations()
    {
        // Arrange: Instantiate ViewModel with mocked services to load presets
        var mockSsl = new Mock<ISslInspectionService>();
        var mockProxy = new Mock<IProxyService>();
        var mockHistory = new Mock<IHistoryService>();
        mockHistory.Setup(h => h.GetHistoryAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<InspectionHistoryEntry>());

        var vm = new MainViewModel(mockSsl.Object, mockProxy.Object, mockHistory.Object);
        var activePresets = vm.Presets
            .Where(p => !p.Host.Contains("badssl.com"))
            .ToList();

        // Act: Run certificate validation in parallel
        var tasks = activePresets.Select(preset => VerifyPresetAsync(preset));
        var results = await Task.WhenAll(tasks);

        // Assert: Verify all presets passed without failures
        var failures = results.Where(r => !string.IsNullOrEmpty(r)).ToList();
        if (failures.Count > 0)
        {
            var aggregatedMessage = "Preset verification failed for some endpoints:\n" + string.Join("\n", failures);
            Assert.Fail(aggregatedMessage);
        }
    }

    private async Task<string?> VerifyPresetAsync(EndpointPreset preset)
    {
        using var tcpClient = new TcpClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        try
        {
            await tcpClient.ConnectAsync(preset.Host, preset.Port, cts.Token);
            using var stream = tcpClient.GetStream();
            using var sslStream = new SslStream(stream, false, (sender, certificate, chain, errors) => true);
            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = preset.Host,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
            }, cts.Token);

            var remoteCert = sslStream.RemoteCertificate;
            if (remoteCert == null)
            {
                return $"[{preset.DisplayName}] Remote server returned a null certificate.";
            }

            using var cert2 = new X509Certificate2(remoteCert);
            
            // Validate Thumbprint (must match one of the expected list)
            string actualThumbprint = cert2.Thumbprint.ToUpperInvariant();
            if (string.IsNullOrWhiteSpace(preset.KnownThumbprint))
            {
                return $"[{preset.DisplayName}] KnownThumbprint is not configured in the preset.";
            }

            var expectedThumbprints = preset.KnownThumbprint
                .Split(new[] { ',', ';', '|' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Replace(" ", "").Replace(":", "").ToUpperInvariant())
                .ToList();

            if (!expectedThumbprints.Contains(actualThumbprint))
            {
                return $"[{preset.DisplayName}] Thumbprint MISMATCH! Expected: {preset.KnownThumbprint}, Actual online: {actualThumbprint}";
            }

            // Validate Expiration Date (online expiration must not be past the known date, i.e., cert is valid)
            if (preset.KnownCertExpirationDate.HasValue)
            {
                if (DateTime.UtcNow > cert2.NotAfter)
                {
                    return $"[{preset.DisplayName}] Certificate has EXPIRED online! (NotAfter: {cert2.NotAfter:yyyy-MM-dd})";
                }
            }

            return null;
        }
        catch (Exception ex)
        {
            bool isCiCd = Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true";
            if (isCiCd)
            {
                return $"[{preset.DisplayName}] Connection/SSL Error: {ex.Message}";
            }
            else
            {
                // Locally, log the warning but do not break the test run (offline or proxy-only environment support)
                Console.WriteLine($"[Local Warning] [{preset.DisplayName}] Connection skipped/failed: {ex.Message}");
                return null;
            }
        }
    }
}
