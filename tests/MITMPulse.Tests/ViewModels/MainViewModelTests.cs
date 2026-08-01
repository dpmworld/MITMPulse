using Moq;
using MITMPulse.Models;
using MITMPulse.Services;
using MITMPulse.ViewModels;
using Xunit;

namespace MITMPulse.Tests.ViewModels;

public class MainViewModelTests
{
    private readonly Mock<ISslInspectionService> _mockSslService = new();
    private readonly Mock<IProxyService> _mockProxyService = new();
    private readonly Mock<IHistoryService> _mockHistoryService = new();
    private readonly MainViewModel _sut;

    public MainViewModelTests()
    {
        _mockHistoryService.Setup(h => h.GetHistoryAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<InspectionHistoryEntry>());

        _sut = new MainViewModel(_mockSslService.Object, _mockProxyService.Object, _mockHistoryService.Object);
    }

    [Fact]
    public void Constructor_InitializesPresets_WithNetScalerAsFirstPreset()
    {
        // Assert
        Assert.NotEmpty(_sut.Presets);
        Assert.Equal("NetScaler Gateway Service", _sut.Presets.First().DisplayName);
        Assert.Equal("global-all.g.nssvc.net", _sut.Presets.First().Host);
        Assert.Equal(443, _sut.Presets.First().Port);
        Assert.Equal("global-all.g.nssvc.net:443", _sut.TargetInput);
    }

    [Fact]
    public async Task InspectEndpointAsync_EmptyTargetInput_SetsStatusMessage()
    {
        // Arrange
        _sut.TargetInput = "   ";

        // Act
        await _sut.InspectEndpointAsync();

        // Assert
        Assert.Equal("Please specify a target endpoint.", _sut.StatusMessage);
        _mockSslService.Verify(s => s.InspectEndpointAsync(
            It.IsAny<string>(), It.IsAny<int>(), It.IsAny<ProxySettings>(), It.IsAny<string>(), It.IsAny<EndpointPreset?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task InspectEndpointAsync_ValidHost_CallsSslInspectionService()
    {
        // Arrange
        _sut.TargetInput = "global-all.g.nssvc.net:443";
        var expectedResult = new SslInspectionResult
        {
            TargetHost = "global-all.g.nssvc.net",
            TargetPort = 443,
            IsSuccess = true,
            TlsVersion = "Tls13",
            IsSslInspectionDetected = false
        };

        _mockSslService.Setup(s => s.InspectEndpointAsync(
            "global-all.g.nssvc.net", 443, It.IsAny<ProxySettings>(), It.IsAny<string>(), It.IsAny<EndpointPreset?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedResult);

        // Act
        await _sut.InspectEndpointAsync();

        // Assert
        Assert.False(_sut.IsLoading);
        Assert.NotNull(_sut.InspectionResult);
        Assert.Equal(expectedResult, _sut.InspectionResult);
        Assert.Equal("DIRECT CONNECTION (No SSL Inspection Detected)", _sut.StatusMessage);
        _mockHistoryService.Verify(h => h.SaveEntryAsync(expectedResult, It.IsAny<CancellationToken>()), Times.Once);
    }
}
