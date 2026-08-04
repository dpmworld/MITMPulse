using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using MITMPulse.Models;

namespace MITMPulse.Services;

public class ProxyService : IProxyService
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINHTTP_PROXY_INFO
    {
        public uint dwAccessType;
        public IntPtr lpszProxy;
        public IntPtr lpszProxyBypass;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
    {
        public bool fAutoDetect;
        public IntPtr lpszAutoConfigUrl;
        public IntPtr lpszProxy;
        public IntPtr lpszProxyBypass;
    }

    private const uint WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3;

    [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WinHttpGetDefaultProxyConfiguration(out WINHTTP_PROXY_INFO pProxyInfo);

    [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WinHttpGetIEProxyConfigForCurrentUser(ref WINHTTP_CURRENT_USER_IE_PROXY_CONFIG pProxyConfig);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr hMem);

    public IWebProxy? GetWebProxy(ProxySettings settings)
    {
        return settings.Mode switch
        {
            ProxyMode.Direct => null,
            ProxyMode.System => HttpClient.DefaultProxy,
            ProxyMode.WinHttp => GetWinHttpProxy(),
            ProxyMode.Custom when !string.IsNullOrWhiteSpace(settings.Host) => new WebProxy(settings.Host, settings.Port)
            {
                Credentials = !string.IsNullOrWhiteSpace(settings.Username)
                    ? new NetworkCredential(settings.Username, settings.Password)
                    : null
            },
            _ => null
        };
    }

    public (string ConfigType, string PacUrl, string StaticProxy) GetSystemProxyInfo()
    {
        try
        {
            var config = new WINHTTP_CURRENT_USER_IE_PROXY_CONFIG();
            if (WinHttpGetIEProxyConfigForCurrentUser(ref config))
            {
                try
                {
                    string pacUrl = config.lpszAutoConfigUrl != IntPtr.Zero
                        ? Marshal.PtrToStringUni(config.lpszAutoConfigUrl) ?? string.Empty
                        : string.Empty;

                    string staticProxy = config.lpszProxy != IntPtr.Zero
                        ? Marshal.PtrToStringUni(config.lpszProxy) ?? string.Empty
                        : string.Empty;

                    string type;
                    if (!string.IsNullOrWhiteSpace(pacUrl))
                    {
                        type = "Script PAC (Auto-Config)";
                    }
                    else if (config.fAutoDetect)
                    {
                        type = "Auto-Detect WPAD";
                    }
                    else if (!string.IsNullOrWhiteSpace(staticProxy))
                    {
                        type = "Static Proxy";
                    }
                    else
                    {
                        type = "Direct (No Proxy Configured)";
                    }

                    return (type, pacUrl, staticProxy);
                }
                finally
                {
                    if (config.lpszAutoConfigUrl != IntPtr.Zero) GlobalFree(config.lpszAutoConfigUrl);
                    if (config.lpszProxy != IntPtr.Zero) GlobalFree(config.lpszProxy);
                    if (config.lpszProxyBypass != IntPtr.Zero) GlobalFree(config.lpszProxyBypass);
                }
            }
        }
        catch
        {
            // Fallback
        }

        return ("Direct / System Default", string.Empty, string.Empty);
    }

    private static IWebProxy? GetWinHttpProxy()
    {
        try
        {
            if (WinHttpGetDefaultProxyConfiguration(out var proxyInfo))
            {
                try
                {
                    if (proxyInfo.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY && proxyInfo.lpszProxy != IntPtr.Zero)
                    {
                        string proxyStr = Marshal.PtrToStringUni(proxyInfo.lpszProxy) ?? string.Empty;
                        string bypassStr = proxyInfo.lpszProxyBypass != IntPtr.Zero
                            ? Marshal.PtrToStringUni(proxyInfo.lpszProxyBypass) ?? string.Empty
                            : string.Empty;

                        if (!string.IsNullOrWhiteSpace(proxyStr))
                        {
                            string cleanProxy = proxyStr;
                            if (cleanProxy.Contains('='))
                            {
                                var parts = cleanProxy.Split(';', StringSplitOptions.RemoveEmptyEntries);
                                string? httpPart = parts.FirstOrDefault(p => p.StartsWith("http=", StringComparison.OrdinalIgnoreCase) || p.StartsWith("https=", StringComparison.OrdinalIgnoreCase)) ?? parts.FirstOrDefault();
                                if (httpPart != null && httpPart.Contains('='))
                                {
                                    cleanProxy = httpPart.Split('=')[1];
                                }
                            }

                            var webProxy = new WebProxy(cleanProxy);
                            if (!string.IsNullOrWhiteSpace(bypassStr))
                            {
                                string[] bypasses = bypassStr.Split(';', StringSplitOptions.RemoveEmptyEntries);
                                webProxy.BypassList = bypasses;
                            }
                            return webProxy;
                        }
                    }
                }
                finally
                {
                    if (proxyInfo.lpszProxy != IntPtr.Zero) GlobalFree(proxyInfo.lpszProxy);
                    if (proxyInfo.lpszProxyBypass != IntPtr.Zero) GlobalFree(proxyInfo.lpszProxyBypass);
                }
            }
        }
        catch
        {
            // Fallback if P/Invoke fails
        }

        return null;
    }
}
