# MITMPulse

**MITMPulse** is a portable, stand-alone Windows desktop application built with C# and .NET 8 WPF, featuring a modern Windows 11 Fluent UI (powered by [WPF-UI](https://github.com/lepoco/wpfui)).

*Application developed with the help of AI (Agentic Coding)*

Author: **Francesco Dipietromaria**  
Website: [www.dpmworld.net](https://www.dpmworld.net)  

---

## 🌟 Features & Architecture

### 🔒 SSL/TLS & MITM Proxy Inspection Engine
- **Endpoint Inspection**: Inspects any remote SSL/TLS endpoint (Host:Port). Automatically sanitizes user input (strips `http://`/`https://` and URL pathing) and defaults to **Port 443** when omitted.
- **SSL Inspection / MITM Proxy Detection**:
  - Differentiates between legitimate internal **Enterprise PKI** certificates on intranet/private hosts (`.local`, `.lan`, `.corp`, `10.x.x.x`, `192.168.x.x`) versus **SSL Interception Proxies** (Zscaler, Fortinet, Palo Alto, Blue Coat) re-signing public domain certificates.
- **Smart Expired Certificate & False-Positive Shield**:
  - Differentiates between expired certificates issued by legitimate public CAs (e.g., COMODO, Let's Encrypt, Sectigo) versus true MITM proxies, preventing false-positive proxy alerts on test endpoints (`expired.badssl.com`).
  - **Baseline Expiration Fallback**: When a pre-coded baseline certificate reaches its expiration date, the engine automatically falls back to live online public CA chain verification.
- **Visual Status Indicators (Fluent Icons)**:
  - 👁️ **Red Eye (`Eye24`)**: Confirmed MITM SSL Inspection active (enterprise proxy re-signing detected).
  - ⚠️ **Orange Warning (`Warning24`)**: Certificate expired or domain error on a public endpoint (direct connection).
  - 🟢 **Green Checkmark (`CheckmarkCircle24`)**: Direct secure connection verified against trusted public Root CAs.
- **GoDaddy R1/G2 Hierarchy & Cross-Certificate Diagnostics**:
  - Native support for GoDaddy & Starfield Root CAs (`GoDaddy TLS Root CA - R1`, `R1v1` intermediate).
  - Emits specific diagnostic warnings if a NetScaler or server is missing the `R1->G2` cross-certificate, preventing client trust false positives (referencing [Go Daddy TLS Certificate not trusted](https://www.dpmworld.net/2026/07/31/go-daddy-tls-certificate-not-trusted/)).
- **Subject Alternative Names (SAN)**: Full extraction and display of Subject Alternative Names (DNS & IP SANs) in both the summary view and certificate chain details.
- **HSTS Security Header Check**: Queries HTTP `Strict-Transport-Security` headers to verify HSTS compliance.
- **TLS Version & Cipher Suite Metrics**: Displays negotiated protocol versions (TLS 1.2, TLS 1.3) and negotiated Cipher Suites.
- **Certificate Pinning**: Optional validation against expected SHA-1 certificate thumbprints with preset fallback.
- **Proxy Modes & PAC/WinHTTP Tunneling**: Supports **Direct** socket connections, **System Proxy** (WinINet / System with automatic **PAC script** execution & HTTP `CONNECT` tunneling), **WinHTTP Proxy** (`netsh winhttp` P/Invoke native system proxy reader), or **Custom** explicit HTTP/SOCKS proxies with mandatory configuration validation and authentication.

### 🏢 Predefined Target Presets
Pre-populated with high-priority enterprise cloud endpoints and live certificate baselines:
1. **Citrix NetScaler Gateway Service** (`global-all.g.nssvc.net:443`) — *Citrix DaaS Control Plane*
2. **Citrix Workspace Agent Hub (EU)** (`agenthub-eu.citrixworkspacesapi.net:443`) — *Citrix DaaS Agent Control Plane (Europe)*
3. **Citrix Workspace Agent Hub (US)** (`agenthub-us.citrixworkspacesapi.net:443`) — *Citrix DaaS Agent Control Plane (United States)*
4. **Citrix Workspace Agent Hub (AP-S)** (`agenthub-ap-s.citrixworkspacesapi.net:443`) — *Citrix DaaS Agent Control Plane (Asia-Pacific)*
5. **Microsoft Entra ID / Azure AD** (`login.microsoftonline.com:443`) — *Cloud Authentication & SSO*
6. **Azure Virtual Desktop Gateway** (`rdgateway.wvd.microsoft.com:443`) — *Microsoft AVD Gateway Service*
7. **Microsoft Teams** (`teams.microsoft.com:443`) — *Microsoft Teams Web & Native Client*
8. **Office 365 Exchange** (`outlook.office365.com:443`) — *Exchange Online Mail Services*
9. **GitHub Services** (`github.com:443`) — *GitHub & Git over HTTPS (Sectigo/DigiCert/USERTrust)*
10. **Amazon S3 API** (`s3.amazonaws.com:443`) — *AWS S3 Cloud Storage API*
11. **Docker Hub Registry** (`registry-1.docker.io:443`) — *Container Image Registry*
12. **Zoom Cloud Meetings** (`zoom.us:443`) — *Zoom Video Conferencing*
13. **Google Public Web** (`google.com:443`) — *Google Public Edge (Google Trust Services)*
14. **Cloudflare Public Edge** (`cloudflare.com:443`) — *Cloudflare CDN Edge*
15. **BadSSL Expired (Test)** (`expired.badssl.com:443`) — *Diagnostic Expired Cert Test (COMODO/Let's Encrypt)*
16. **BadSSL Self-Signed (Test)** (`self-signed.badssl.com:443`) — *Diagnostic Self-Signed Test*
17. **BadSSL Untrusted Root (Test)** (`untrusted-root.badssl.com:443`) — *Diagnostic Untrusted Root Test*

### 🎨 User Experience, Reliability & Performance
- **Windows 11 Light Theme & Dynamic Auto-Sizing**: Clean Fluent Design with Windows 11 `ui:TitleBar` controls and dynamic column auto-sizing preventing string truncation in Italian, English, and French.
- **Thread-Safe Startup & Exception Shield**: Thread-safe synchronous settings initialization preventing UI thread sync-over-async deadlocks on startup, backed by global `DispatcherUnhandledException` diagnostic dialogs.
- **Keyboard Shortcuts**: Instant scan execution by pressing **Enter** inside the endpoint field.
- **Optimized Stand-Alone Binary**: Compressed Single-File build using `<EnableCompressionInSingleFile>true</EnableCompressionInSingleFile>`, shrinking total binary size from 192 MB to **~76 MB** (~60% reduction).
- **Multilingual Support & Dynamic XAML Binding**: Built-in support for English, Italian, and French with live runtime language switching.
- **Persistent User Settings**: User configuration (language override, custom proxy settings) is automatically saved to `%APPDATA%\dpmworld\MITMPulse\settings.json`.

### 🌐 Supported Languages & Internationalization

**MITMPulse** natively supports multiple languages with automatic Windows OS locale detection and real-time UI switching:
- 🇬🇧 **English (en-US)** (`Strings.resx` — Default Neutral Fallback)
- 🇮🇹 **Italiano (it-IT)** (`Strings.it.resx`)
- 🇫🇷 **Français (fr-FR)** (`Strings.fr.resx`)

**Language Override Feature**:
Users can explicitly force their preferred language from the **Application & Proxy Settings** tab (`Auto (System Language)`, `English (en-US)`, `Italiano (it-IT)`, `Français (fr-FR)`). The selection is instantly applied across all XAML views in real-time without restarting the application.

---

## 💻 System Requirements

- **Operating System**: Windows 10 (version 1809+) or Windows 11 x64
- **Runtime**: .NET 8 Runtime (self-contained within the executable, no installation or administrator rights required)

---

## 🛠️ Build & Development Instructions

### Build Solution
```cmd
dotnet build MITMPulse.sln
```

### Run Unit Tests (xUnit)
```cmd
dotnet test MITMPulse.sln
```

### Publish Stand-Alone Compressed Single-File Executable
```cmd
dotnet publish src/MITMPulse/MITMPulse.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

Output executable path:
`./src/MITMPulse/bin/Release/net8.0-windows10.0.18362.0/win-x64/publish/MITMPulse.exe`

---

## ☕ Support & Buy Me a Coffee

If you like **MITMPulse** or if it saved you time during network troubleshooting, consider buying me a coffee to support its open-source development:

[![PayPal Donate](https://img.shields.io/badge/Buy_Me_A_Coffee-PayPal.Me-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/dpmworld)

---

## ⚠️ Disclaimer & Limitation of Liability

**MITMPulse** is provided "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHOR (**Francesco Dipietromaria** / [www.dpmworld.net](https://www.dpmworld.net)) BE LIABLE FOR ANY CLAIM, DAMAGES, DATA LOSS, NETWORK DISRUPTIONS, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This software is designed solely for legitimate network administration, SSL inspection diagnostics, and security verification by authorized personnel. Users are solely responsible for ensuring that their use of this software complies with all applicable local, national, and international laws and organizational policies.

---
Copyright © 2026 **Francesco Dipietromaria** ([www.dpmworld.net](https://www.dpmworld.net))
