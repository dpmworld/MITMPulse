using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MITMPulse.Models;

namespace MITMPulse.Services;

public class SslInspectionService : ISslInspectionService
{
    private readonly IProxyService _proxyService;

    public SslInspectionService(IProxyService proxyService)
    {
        _proxyService = proxyService;
    }

    public async Task<SslInspectionResult> InspectEndpointAsync(
        string targetHost,
        int targetPort,
        ProxySettings proxySettings,
        string? expectedThumbprint = null,
        EndpointPreset? preset = null,
        CancellationToken cancellationToken = default)
    {
        var result = new SslInspectionResult
        {
            TargetHost = targetHost,
            TargetPort = targetPort,
            Timestamp = DateTime.Now
        };

        if (string.IsNullOrWhiteSpace(targetHost))
        {
            result.IsSuccess = false;
            result.ErrorMessage = "Target host cannot be empty.";
            return result;
        }

        try
        {
            using var tcpClient = new TcpClient();

            // Connect timeout 10s
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));

            if (proxySettings.Mode == ProxyMode.System || proxySettings.Mode == ProxyMode.WinHttp)
            {
                result.IsSystemProxyUsed = true;
                var sysInfo = _proxyService.GetProxyDetails(proxySettings.Mode);
                result.SystemProxyConfigType = sysInfo.ConfigType;
                result.PacScriptUrl = sysInfo.PacUrl;
            }

            var webProxy = _proxyService.GetWebProxy(proxySettings);
            var networkStream = await EstablishConnectionAsync(targetHost, targetPort, webProxy, result, tcpClient, timeoutCts.Token).ConfigureAwait(false);

            X509Certificate2? capturedCert = null;
            X509Chain? capturedChain = null;
            SslPolicyErrors capturedErrors = SslPolicyErrors.None;

            using var sslStream = new SslStream(
                networkStream,
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (sender, certificate, chain, errors) =>
                {
                    if (certificate is X509Certificate2 cert2)
                    {
                        capturedCert = new X509Certificate2(cert2);
                    }
                    else if (certificate != null)
                    {
                        capturedCert = new X509Certificate2(certificate);
                    }

                    if (chain != null)
                    {
                        capturedChain = new X509Chain();
                        capturedChain.ChainPolicy = chain.ChainPolicy;
                        capturedChain.Build(capturedCert ?? new X509Certificate2(certificate!));
                    }
                    capturedErrors = errors;
                    return true; // Accept certificate during inspection to inspect details
                });

            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
            };

            await sslStream.AuthenticateAsClientAsync(sslOptions, timeoutCts.Token);

            result.IsSuccess = true;
            result.TlsVersion = sslStream.SslProtocol.ToString();
            result.CipherSuite = sslStream.NegotiatedCipherSuite.ToString();

            if (capturedCert != null)
            {
                result.ServerCertificate = ExtractCertificateDetail(capturedCert);

                if (capturedChain != null)
                {
                    foreach (var element in capturedChain.ChainElements)
                    {
                        result.CertificateChain.Add(ExtractCertificateDetail(element.Certificate));
                    }
                }
                else
                {
                    // Fallback to building chain manually
                    using var chain = new X509Chain();
                    chain.Build(capturedCert);
                    foreach (var element in chain.ChainElements)
                    {
                        result.CertificateChain.Add(ExtractCertificateDetail(element.Certificate));
                    }
                }

                // Certificate Pinning Validation
                string? pinExpected = expectedThumbprint;
                bool isUserSuppliedPin = !string.IsNullOrWhiteSpace(expectedThumbprint);

                if (!isUserSuppliedPin && preset?.KnownThumbprint != null)
                {
                    pinExpected = preset.KnownThumbprint;
                }

                if (!string.IsNullOrWhiteSpace(pinExpected))
                {
                    string cleanActual = capturedCert.Thumbprint.Replace(" ", "").Replace(":", "").ToUpperInvariant();
                    string[] expectedList = pinExpected.Split(new[] { ',', ';', '|' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(p => p.Replace(" ", "").Replace(":", "").ToUpperInvariant())
                        .ToArray();

                    if (expectedList.Contains(cleanActual))
                    {
                        result.PinningStatus = "Pinning Matched";
                    }
                    else if (!isUserSuppliedPin && preset?.KnownCertExpirationDate.HasValue == true && DateTime.UtcNow > preset.KnownCertExpirationDate.Value)
                    {
                        result.PinningStatus = $"Baseline Expiration Fallback (Server Cert Renewed on {capturedCert.NotBefore:yyyy-MM-dd})";
                    }
                    else
                    {
                        result.PinningStatus = $"Pinning MISMATCH! Expected: {pinExpected}, Actual: {capturedCert.Thumbprint}";
                    }
                }

                // Analyze for SSL Inspection / MITM
                AnalyzeSslInspection(result, capturedCert, result.CertificateChain, capturedErrors, preset);

                // Check HSTS Header
                await CheckHstsHeaderAsync(result, proxySettings, timeoutCts.Token);
            }
            else
            {
                result.IsSuccess = false;
                result.ErrorMessage = "Remote server did not provide an X.509 SSL certificate.";
            }
        }
        catch (Exception ex)
        {
            result.IsSuccess = false;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    private static CertificateDetail ExtractCertificateDetail(X509Certificate2 cert)
    {
        var detail = new CertificateDetail
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            ValidFrom = cert.NotBefore,
            ValidTo = cert.NotAfter,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "Unknown",
            KeyAlgorithm = cert.GetKeyAlgorithm(),
            IsSelfSigned = cert.Subject.Equals(cert.Issuer, StringComparison.OrdinalIgnoreCase),
            SubjectAlternativeNames = ExtractSubjectAlternativeNames(cert)
        };

        return detail;
    }

    private static List<string> ExtractSubjectAlternativeNames(X509Certificate2 cert)
    {
        var sans = new List<string>();
        try
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid?.Value == "2.5.29.17") // SAN OID
                {
                    var sanExtension = new X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical);
                    foreach (var name in sanExtension.EnumerateDnsNames())
                    {
                        sans.Add($"DNS:{name}");
                    }
                    foreach (var ip in sanExtension.EnumerateIPAddresses())
                    {
                        sans.Add($"IP:{ip}");
                    }
                }
            }
        }
        catch
        {
            // Ignore SAN parsing errors if malformed
        }
        return sans;
    }

    private static void AnalyzeSslInspection(
        SslInspectionResult result,
        X509Certificate2 cert,
        List<CertificateDetail> chain,
        SslPolicyErrors policyErrors,
        EndpointPreset? preset = null)
    {
        var reasons = new List<string>();
        bool isInternalTarget = IsInternalOrPrivateHost(result.TargetHost);

        var rootCert = chain.LastOrDefault();
        string rootIssuer = rootCert?.Issuer ?? string.Empty;
        string rootSubject = rootCert?.Subject ?? string.Empty;

        // 1. Known enterprise proxy / middlebox CA keywords (Absolute priority for proxy detection)
        string[] proxyKeywords = new[]
        {
            "zscaler", "fortinet", "fortigate", "palo alto", "bluecoat", "cisco umbrella",
            "untangle", "sophos decrypt", "forcepoint", "sonicwall", "barracuda",
            "inspection", "interception", "mitm"
        };

        bool hasProxyKeyword = false;
        foreach (var keyword in proxyKeywords)
        {
            if (rootIssuer.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                rootSubject.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                cert.Issuer.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                hasProxyKeyword = true;
                reasons.Add($"Issuer/Root CA contains enterprise proxy keyword '{keyword}' ({rootIssuer}).");
                break;
            }
        }

        bool isKnownPublicRoot = IsKnownPublicRootCa(cert.Issuer) || (rootCert != null && IsKnownPublicRootCa(rootSubject));
        bool isExpired = DateTime.UtcNow > cert.NotAfter || DateTime.UtcNow < cert.NotBefore;

        if (hasProxyKeyword)
        {
            result.IsSslInspectionDetected = true;
            result.InspectionReason = string.Join(" ", reasons);
            return;
        }

        // 2. Check for Expired Certificates issued by known Public CAs (Exclude False Positive MITM)
        if (isExpired && isKnownPublicRoot)
        {
            result.IsSslInspectionDetected = false;
            result.InspectionReason = $"CERTIFICATE EXPIRED: The server certificate expired on {cert.NotAfter:yyyy-MM-dd HH:mm:ss UTC}. No SSL Inspection proxy detected (Original public issuer: {cert.Issuer}).";
            return;
        }

        // 3. Preset Baseline Expectation Check (Validation against pre-configured public CA list)
        if (preset != null && preset.ExpectedPublicIssuers.Length > 0)
        {
            bool matchesExpectedIssuer = preset.ExpectedPublicIssuers.Any(expected =>
                cert.Issuer.Contains(expected, StringComparison.OrdinalIgnoreCase) ||
                rootSubject.Contains(expected, StringComparison.OrdinalIgnoreCase));

            if (!matchesExpectedIssuer && !isKnownPublicRoot)
            {
                result.IsSslInspectionDetected = true;
                result.InspectionReason = $"CONFIRMED SSL INSPECTION (100% Certainty)! Expected public issuer for '{preset.DisplayName}' is '{string.Join("/", preset.ExpectedPublicIssuers)}', but received '{cert.Issuer}' from proxy.";

                if (preset.KnownCertExpirationDate.HasValue)
                {
                    result.InspectionReason += $" (Baseline expiration: {preset.KnownCertExpirationDate.Value:yyyy-MM-dd}).";
                }
                return;
            }
        }

        // 4. SSL Inspection Decision Matrix for general targets
        if (!isKnownPublicRoot && !isInternalTarget)
        {
            result.IsSslInspectionDetected = true;
            result.InspectionReason = $"Target '{result.TargetHost}' is a public endpoint, but its certificate chain is signed by a private/internal CA ({cert.Issuer}). SSL Inspection proxy active.";
        }
        else if (isInternalTarget && !isKnownPublicRoot)
        {
            result.IsSslInspectionDetected = false;
            result.InspectionReason = $"Internal target '{result.TargetHost}' is using a valid internal Enterprise CA ({cert.Issuer}). No SSL inspection detected.";
        }
        else
        {
            result.IsSslInspectionDetected = false;
            result.InspectionReason = "Certificate chain originates from a trusted public Root CA. Direct connection established.";
        }

        if (preset?.KnownCertExpirationDate.HasValue == true)
        {
            if (DateTime.UtcNow > preset.KnownCertExpirationDate.Value)
            {
                result.InspectionReason += $" [Target certificate renewed past baseline date {preset.KnownCertExpirationDate.Value:yyyy-MM-dd} (Current cert valid until {cert.NotAfter:yyyy-MM-dd})].";
            }
        }

        // Check for GoDaddy R1 hierarchy / cross-certificate note per dpmworld.net article
        if (cert.Issuer.Contains("GoDaddy", StringComparison.OrdinalIgnoreCase) || rootSubject.Contains("GoDaddy", StringComparison.OrdinalIgnoreCase))
        {
            bool hasCrossCert = chain.Any(c => c.Subject.Contains("R1 to G2", StringComparison.OrdinalIgnoreCase) || c.Issuer.Contains("G2", StringComparison.OrdinalIgnoreCase));
            if (cert.Issuer.Contains("R1v1", StringComparison.OrdinalIgnoreCase) && !hasCrossCert)
            {
                result.InspectionReason += " [Note: GoDaddy R1 hierarchy detected. Ensure GoDaddy R1->G2 Cross-Certificate is linked if legacy client trust errors occur].";
            }
        }

        if (result.PinningStatus.StartsWith("Pinning MISMATCH"))
        {
            result.InspectionReason += " [Certificate Pinning MISMATCH!]";
        }
    }

    private static bool IsInternalOrPrivateHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        if (!host.Contains('.')) return true;

        string lowerHost = host.ToLowerInvariant();
        string[] internalTlds = new[] { ".local", ".lan", ".corp", ".internal", ".home", ".test", ".domain", ".intranet", ".priv" };
        foreach (var tld in internalTlds)
        {
            if (lowerHost.EndsWith(tld)) return true;
        }

        if (System.Net.IPAddress.TryParse(host, out var ip))
        {
            byte[] bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                if (bytes[0] == 127 || bytes[0] == 10) return true;
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                if (bytes[0] == 192 && bytes[1] == 168) return true;
            }
            else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                if (System.Net.IPAddress.IsLoopback(ip)) return true;
            }
        }

        return false;
    }

    private static bool IsKnownPublicRootCa(string subject)
    {
        string[] publicRootCas = new[]
        {
            "GoDaddy", "Go Daddy", "Starfield", "DigiCert", "Sectigo", "Let's Encrypt",
            "GlobalSign", "Entrust", "Baltimore CyberTrust", "ISRG Root", "GTS Root",
            "Google Trust Services", "Amazon", "Microsoft", "USERTrust", "AAA Certificate Services",
            "VeriSign", "GeoTrust", "Thawte", "QuoVadis", "Buypass", "IdenTrust", "Certum",
            "Actalis", "Trustwave", "Network Solutions", "Comodo", "Camerfirma", "ZeroSSL"
        };

        foreach (var ca in publicRootCas)
        {
            if (subject.Contains(ca, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private async Task CheckHstsHeaderAsync(SslInspectionResult result, ProxySettings proxySettings, CancellationToken cancellationToken)
    {
        try
        {
            var handler = new HttpClientHandler
            {
                Proxy = _proxyService.GetWebProxy(proxySettings),
                UseProxy = proxySettings.Mode != ProxyMode.Direct,
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
            };

            using var httpClient = new HttpClient(handler);
            httpClient.Timeout = TimeSpan.FromSeconds(5);

            string url = $"https://{result.TargetHost}:{result.TargetPort}/";
            using var request = new HttpRequestMessage(HttpMethod.Head, url);
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            if (response.Headers.TryGetValues("Strict-Transport-Security", out var values))
            {
                result.IsHstsSupported = true;
                result.HstsHeaderValue = string.Join("; ", values);
            }
            else
            {
                result.IsHstsSupported = false;
                result.HstsHeaderValue = "Not Exposed";
            }
        }
        catch
        {
            result.IsHstsSupported = false;
            result.HstsHeaderValue = "Not Exposed / Unable to query HTTP headers";
        }
    }

    private static async Task<NetworkStream> EstablishConnectionAsync(
        string targetHost,
        int targetPort,
        IWebProxy? webProxy,
        SslInspectionResult result,
        TcpClient tcpClient,
        CancellationToken cancellationToken)
    {
        var targetUri = new Uri($"https://{targetHost}:{targetPort}");

        if (webProxy != null && !webProxy.IsBypassed(targetUri))
        {
            var proxyUri = webProxy.GetProxy(targetUri);
            if (proxyUri != null && proxyUri != targetUri)
            {
                result.PacResolvedProxy = $"PROXY {proxyUri.Host}:{proxyUri.Port}";

                // Connect TCP socket directly to Proxy Server IP/Host & Port
                await tcpClient.ConnectAsync(proxyUri.Host, proxyUri.Port, cancellationToken).ConfigureAwait(false);
                var stream = tcpClient.GetStream();

                // Build HTTP CONNECT Tunnel Request
                var connectBuilder = new StringBuilder();
                connectBuilder.Append($"CONNECT {targetHost}:{targetPort} HTTP/1.1\r\n");
                connectBuilder.Append($"Host: {targetHost}:{targetPort}\r\n");
                connectBuilder.Append("User-Agent: MITMPulse/1.0\r\n");

                if (webProxy.Credentials != null)
                {
                    var credential = webProxy.Credentials.GetCredential(proxyUri, "Basic");
                    if (credential != null && !string.IsNullOrEmpty(credential.UserName))
                    {
                        string auth = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{credential.UserName}:{credential.Password}"));
                        connectBuilder.Append($"Proxy-Authorization: Basic {auth}\r\n");
                    }
                }

                connectBuilder.Append("\r\n");

                byte[] requestBytes = Encoding.ASCII.GetBytes(connectBuilder.ToString());
                await stream.WriteAsync(requestBytes, 0, requestBytes.Length, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

                // Read HTTP response status line (e.g., HTTP/1.1 200 Connection Established)
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                string? responseLine = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);

                if (string.IsNullOrEmpty(responseLine) || !responseLine.Contains("200"))
                {
                    result.TunnelStatus = $"Failed ({responseLine ?? "No response"})";
                    throw new InvalidOperationException($"Proxy HTTP CONNECT tunnel failed ({proxyUri.Host}:{proxyUri.Port}): {responseLine ?? "No response from proxy"}");
                }

                result.TunnelStatus = "HTTP CONNECT 200 OK (Tunnel Established)";

                // Consume remaining HTTP headers until blank line (\r\n)
                string? headerLine;
                while (!string.IsNullOrEmpty(headerLine = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false)))
                {
                    // Consuming header lines
                }

                return stream;
            }
        }

        result.PacResolvedProxy = "DIRECT (Bypassed / Direct Connection)";
        result.TunnelStatus = "Direct TCP Socket (No Tunnel)";

        // Direct TCP socket connection if no proxy or bypassed
        await tcpClient.ConnectAsync(targetHost, targetPort, cancellationToken).ConfigureAwait(false);
        return tcpClient.GetStream();
    }
}
