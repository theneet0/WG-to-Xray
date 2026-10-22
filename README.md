# WireGuard to Xray Outbound Converter

A fast, lightweight, and minimal client-side web application to convert WireGuard (`.conf`) configurations into [Xray-core](https://github.com/XTLS/Xray-core) outbound JSON format (compatible with Xray-core 26.x / 26.6.1).

🌐 **Live Web Application**: [https://theneet0.github.io/wg-to-xray/](https://theneet0.github.io/wg-to-xray/)

---

## ✨ Features

- **Dual Output Generation**:
  - **WireGuard URI Link (`wireguard://`)**: Ready-to-use client link format (`wireguard://<private-key>@<endpoint>?address=...&publickey=...#<tag>`) compatible with mobile and desktop VPN clients.
  - **Xray Outbound JSON**: Full Xray-core outbound JSON with fine-tuned parameters.
- **View Filter Modes**: Toggle between `All`, `WireGuard Link`, or `Xray JSON` views.
- **Material Minimal Black Theme**: Deep OLED black palette (`#000000`), subtle borders, high contrast, and clean typography.
- **100% Client-Side & Private**: Runs entirely in your browser with zero external network requests or server logging.
- **Drag & Drop + File Picker**: Drop `.conf` or `.txt` files directly or browse from your device.
- **Automatic Tag from File Name**: The WireGuard tag/remark is automatically detected from the uploaded configuration file name (without extension), with support for custom manual overrides.
- **Clean Conversion (No Extra Setting Injection)**: Extra parameters like `MTU` and `PersistentKeepalive` are only included in the converted output if they were explicitly configured in the original WireGuard file. No arbitrary default values are forced into your converted configuration.
- **Comprehensive WireGuard Parameter Support**:
  - Full multi-line and comma-separated `Address`, `DNS` (mapped to Xray `remoteDNS` and URI `dns`), and `AllowedIPs`.
  - Supports standard and alternative parameter names (`PrivateKey`/`SecretKey`, `PublicKey`/`Pubkey`, `PersistentKeepalive`/`Keepalive`, `PresharedKey`/`Psk`, etc.).
  - WireGuard Reserved Bytes: Supports both comma/bracket lists (`[1, 2, 3]`) and 4-character base64 representations (e.g. `AAAA`).
- **Configurable Outbound Options**:
  - `domainStrategy` (`ForceIP`, `ForceIPv4`, `ForceIPv6`, `ForceIPv4v6`, `ForceIPv6v4`)
  - `noKernelTun` (enabled by default for Windows & client environments)
  - `wrapInOutbounds` (optionally wrap in `{"outbounds": [ ... ]}`)
- **Multi-Peer Support**: Accurately parses and maps all peers with endpoints, allowed IPs, pre-shared keys, and persistent keepalive.
- **Syntax Highlighting & Export**: Instant formatted previews with one-click **Copy Link**, **Copy JSON**, and **Download JSON**.

---

## 🚀 Usage

### Option 1: Live GitHub Pages
Open the web app directly in your browser:
👉 **[https://theneet0.github.io/wg-to-xray/](https://theneet0.github.io/wg-to-xray/)**

### Option 2: Local / Offline
Clone the repository and open `index.html` in any modern web browser:

```bash
git clone https://github.com/theneet0/wg-to-xray.git
cd wg-to-xray
# Open index.html directly
```

---

## 🧪 Testing

The conversion logic has been verified with 100% test parity against the Python reference parser across multiple configuration variants and edge cases:

```bash
node test_parity.js
node test_html_script.js
```

---

## 📄 License

MIT License
