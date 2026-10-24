# wg-to-xray

[![Launch Web App](https://img.shields.io/badge/Launch%20Web%20App-theneet0.github.io%2Fwg--to--xray-000000?style=for-the-badge&logo=googlechrome&logoColor=white)](https://theneet0.github.io/wg-to-xray/)

Convert WireGuard configuration files (`.conf`) to Xray-core outbound JSON and `wireguard://` URIs.

Runs client-side in the browser.

## Usage

### Web
Open **[theneet0.github.io/wg-to-xray](https://theneet0.github.io/wg-to-xray/)**

### Local
```bash
git clone https://github.com/theneet0/wg-to-xray.git
cd wg-to-xray
npx serve .
```

### Node.js
```javascript
const { parseWireguardConfig, buildXrayConfig, buildWireguardUri } = require('./converter.js');

const raw = `[Interface]
PrivateKey = aaaaaa...=
Address = 10.0.0.2/32

[Peer]
PublicKey = bbbbbb...=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0`;

const parsed = parseWireguardConfig(raw);
const { config } = buildXrayConfig(parsed, { tag: "vpn" });
const [uri] = buildWireguardUri(parsed, { tag: "vpn" });

console.log(config);
console.log(uri);
```

## License

[MIT](LICENSE)
