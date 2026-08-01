using System.Net;
using MITMPulse.Models;

namespace MITMPulse.Services;

public interface IProxyService
{
    IWebProxy? GetWebProxy(ProxySettings settings);
}
