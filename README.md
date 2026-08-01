# MITMPulse

**MITMPulse** is a portable, stand-alone Windows desktop application built with C# and .NET 8 WPF, featuring a modern Windows 11 Fluent UI (powered by [WPF-UI](https://github.com/lepoco/wpfui)).

Author: **Francesco Dipietromaria**  
Website: [www.dpmworld.net](https://www.dpmworld.net)  

---

## 🌟 Features & Architecture

### 🔒 SSL/TLS & MITM Proxy Inspection Engine
- **Endpoint Inspection**: Inspects any remote SSL/TLS endpoint (Host:Port). Automatically sanitizes user input (strips `http://`/`https://` and URL pathing) and defaults to **Port 443** when omitted.
- **SSL Inspection / MITM Proxy Detection**:
  - Differentiates between legitimate internal **Enterprise PKI** certificates on intranet/private hosts (`.local`, `.lan`, `.corp`, `10.x.x.x`, `192.168.x.x`) versus **SSL Interception Proxies** (Zscaler, Fortinet, Palo Alto, Blue Coat) re-signing public domain certificates.
- **GoDaddy R1/G2 Hierarchy & Cross-Certificate Diagnostics**:
  - Native support for GoDaddy & Starfield Root CAs (`GoDaddy TLS Root CA - R1`, `R1v1` intermediate).
  - Emits specific diagnostic warnings if a NetScaler or server is missing the `R1->G2` cross-certificate, preventing client trust false positives (referencing [Go Daddy TLS Certificate not trusted](https://www.dpmworld.net/2026/07/31/go-daddy-tls-certificate-not-trusted/)).
- **Subject Alternative Names (SAN)**: Full extraction and display of Subject Alternative Names (DNS & IP SANs) in both the summary view and certificate chain details.
- **HSTS Security Header Check**: Queries HTTP `Strict-Transport-Security` headers to verify HSTS compliance.
- **TLS Version & Cipher Suite Metrics**: Displays negotiated protocol versions (TLS 1.2, TLS 1.3) and negotiated Cipher Suites.
- **Certificate Pinning**: Optional validation against expected SHA-1 certificate thumbprints.
- **Proxy Modes**: Supports **Direct** socket connections, **System Proxy** (WinINet / System), or **Custom** explicit HTTP/SOCKS proxies with authentication.

### 🏢 Predefined Target Presets
Pre-populated with high-priority enterprise cloud endpoints that frequently experience SSL Inspection or Certificate Pinning issues:
1. **Citrix NetScaler Gateway Service** (`global-all.g.nssvc.net:443`) — *Citrix DaaS Control Plane*
2. **Citrix Portal** (`citrix.com:443`) — *Official Citrix Portal*
3. **Microsoft Entra ID / Azure AD** (`login.microsoftonline.com:443`) — *Cloud Authentication & SSO*
4. **Microsoft Teams** (`teams.microsoft.com:443`) — *Microsoft Teams Web & Native Client*
5. **Office 365 Exchange** (`outlook.office365.com:443`) — *Exchange Online Mail Services*
6. **GitHub Services** (`github.com:443`) — *GitHub & Git over HTTPS*
7. **Amazon S3 API** (`s3.amazonaws.com:443`) — *AWS S3 Cloud Storage API*
8. **Docker Hub Registry** (`registry-1.docker.io:443`) — *Container Image Registry*
9. **Zoom Cloud Meetings** (`zoom.us:443`) — *Zoom Video Conferencing*
10. **Google Public Web** (`google.com:443`) — *Google Public Edge*
11. **Cloudflare Public Edge** (`cloudflare.com:443`) — *Cloudflare CDN Edge*
12. **BadSSL Expired (Test)** (`expired.badssl.com:443`) — *Diagnostic Expired Cert Test*
13. **BadSSL Self-Signed (Test)** (`self-signed.badssl.com:443`) — *Diagnostic Self-Signed Test*
14. **BadSSL Untrusted Root (Test)** (`untrusted-root.badssl.com:443`) — *Diagnostic Untrusted Root Test*

### 🎨 User Experience & Performance
- **Windows 11 Light Theme**: Clean Fluent Design with Windows 11 `ui:TitleBar` window controls.
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
dotnet build C:\Sviluppo\MITMPulse\MITMPulse.sln
```

### Run Unit Tests (xUnit)
```cmd
dotnet test C:\Sviluppo\MITMPulse\MITMPulse.sln
```

### Publish Stand-Alone Compressed Single-File Executable
```cmd
dotnet publish C:\Sviluppo\MITMPulse\src\MITMPulse\MITMPulse.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

Output executable path:
`C:\Sviluppo\MITMPulse\src\MITMPulse\bin\Release\net8.0-windows10.0.18362.0\win-x64\publish\MITMPulse.exe`

---
Copyright © 2026 **Francesco Dipietromaria** ([www.dpmworld.net](https://www.dpmworld.net))
