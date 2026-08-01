using System.Net;
using System.Net.Http;
using MITMPulse.Models;
using MITMPulse.Services;
using Xunit;

namespace MITMPulse.Tests.Services;

public class ProxyServiceTests
{
    private readonly ProxyService _sut = new();

    [Fact]
    public void GetWebProxy_DirectMode_ReturnsNull()
    {
        // Arrange
        var settings = new ProxySettings { Mode = ProxyMode.Direct };

        // Act
        var result = _sut.GetWebProxy(settings);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void GetWebProxy_SystemMode_ReturnsHttpClientDefaultProxy()
    {
        // Arrange
        var settings = new ProxySettings { Mode = ProxyMode.System };

        // Act
        var result = _sut.GetWebProxy(settings);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(HttpClient.DefaultProxy, result);
    }

    [Fact]
    public void GetWebProxy_CustomModeWithHost_ReturnsWebProxy()
    {
        // Arrange
        var settings = new ProxySettings
        {
            Mode = ProxyMode.Custom,
            Host = "http://10.0.0.1",
            Port = 8080,
            Username = "user",
            Password = "pass"
        };

        // Act
        var result = _sut.GetWebProxy(settings);

        // Assert
        Assert.NotNull(result);
        Assert.IsType<WebProxy>(result);
    }
}
