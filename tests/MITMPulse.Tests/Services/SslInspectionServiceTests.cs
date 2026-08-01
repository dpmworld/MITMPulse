using Moq;
using MITMPulse.Models;
using MITMPulse.Services;
using Xunit;

namespace MITMPulse.Tests.Services;

public class SslInspectionServiceTests
{
    private readonly Mock<IProxyService> _mockProxyService = new();
    private readonly SslInspectionService _sut;

    public SslInspectionServiceTests()
    {
        _sut = new SslInspectionService(_mockProxyService.Object);
    }

    [Fact]
    public async Task InspectEndpointAsync_EmptyHost_ReturnsFailureResult()
    {
        // Arrange
        var proxySettings = new ProxySettings();

        // Act
        var result = await _sut.InspectEndpointAsync("", 443, proxySettings);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Equal("Target host cannot be empty.", result.ErrorMessage);
    }

    [Fact]
    public async Task InspectEndpointAsync_InvalidHost_ReturnsFailureResult()
    {
        // Arrange
        var proxySettings = new ProxySettings();

        // Act
        var result = await _sut.InspectEndpointAsync("invalid.nonexistent.domain.xyz12345", 443, proxySettings);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.NotEmpty(result.ErrorMessage);
    }
}
