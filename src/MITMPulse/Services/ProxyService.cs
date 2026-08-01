using System.Net;
using System.Net.Http;
using MITMPulse.Models;

namespace MITMPulse.Services;

public class ProxyService : IProxyService
{
    public IWebProxy? GetWebProxy(ProxySettings settings)
    {
        return settings.Mode switch
        {
            ProxyMode.Direct => null,
            ProxyMode.System => HttpClient.DefaultProxy,
            ProxyMode.Custom when !string.IsNullOrWhiteSpace(settings.Host) => new WebProxy(settings.Host, settings.Port)
            {
                Credentials = !string.IsNullOrWhiteSpace(settings.Username)
                    ? new NetworkCredential(settings.Username, settings.Password)
                    : null
            },
            _ => null
        };
    }
}
