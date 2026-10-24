# wg-to-xray

[![Launch Web App](https://img.shields.io/badge/Launch%20Web%20App-theneet0.github.io%2Fwg--to--xray-000000?style=for-the-badge&logo=googlechrome&logoColor=white)](https://theneet0.github.io/wg-to-xray/)

A lightweight, zero-dependency client-side converter that transforms standard WireGuard configuration files (`.conf`) into **Xray-core outbound JSON** and standard **`wireguard://` connection URIs**.

Runs 100% in the browser with no server dependencies, build steps, external requests, or network telemetry.

---

## Features

- **Xray Outbound JSON**: Formats WireGuard configurations ready for direct insertion into Xray-core clients/servers.
- **WireGuard URI**: Generates `wireguard://<key>@<endpoint>?<params>#<tag>` share links for one-click mobile and desktop import.
- **WARP & Advanced Parameters**: Full support for Cloudflare WARP `Reserved` bytes (Base64, Hex, Decimal), multiple `[Peer]` blocks, custom MTU, DNS, and keepalive.
- **Privacy First**: Fully client-side processing — your private keys never leave your machine.

---

## Quick Usage

### Web Interface
Open the app directly in your browser:
&rarr; **[https://theneet0.github.io/wg-to-xray/](https://theneet0.github.io/wg-to-xray/)**

### Run Locally
Host locally with zero configuration:
```bash
git clone https://github.com/theneet0/wg-to-xray.git
cd wg-to-xray
npx serve .
```

### Programmatic Usage (Node.js)
```javascript
const { parseWireguardConfig, buildXrayConfig, buildWireguardUri } = require('./converter.js');

const rawConf = `
[Interface]
PrivateKey = aaaaaa...=
Address = 10.0.0.2/32

[Peer]
PublicKey = bbbbbb...=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0
`;

const parsed = parseWireguardConfig(rawConf);
const { config } = buildXrayConfig(parsed, { tag: "prod-vpn" });
const uris = buildWireguardUri(parsed, { tag: "prod-vpn" });

console.log(config);
console.log(uris[0]);
```

---

## License

[MIT](LICENSE)
