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

    [Fact]
    public void BuildDtlsClientHello_ValidHost_ReturnsWellFormedDtlsRecord()
    {
        // Arrange
        string host = "citrix.gateway.example.com";

        // Act
        byte[] datagram = SslInspectionService.BuildDtlsClientHello(host);

        // Assert
        Assert.NotNull(datagram);
        Assert.True(datagram.Length >= 13);
        Assert.Equal(0x16, datagram[0]); // ContentType = Handshake (22)
        Assert.Equal(0xFE, datagram[1]); // Major Version = DTLS (0xFE)
        Assert.Equal(0xFD, datagram[2]); // Minor Version = DTLS 1.2 (0xFD)
    }

    [Fact]
    public async Task TestDtlsOverUdpAsync_InvalidHost_ReturnsFalse()
    {
        // Arrange
        string invalidHost = "invalid.nonexistent.domain.xyz12345";

        // Act
        bool isSupported = await SslInspectionService.TestDtlsOverUdpAsync(invalidHost, 443);

        // Assert
        Assert.False(isSupported);
    }
}
