const assert = require("assert");
const converter = require("./converter.js");

const testCases = [
  {
    name: "Basic config",
    conf: `
[Interface]
PrivateKey = aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11=
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11=",
        peers: [
          {
            publicKey: "bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22=",
            endpoint: "198.51.100.1:51820",
            allowedIPs: ["0.0.0.0/0", "::/0"],
            keepAlive: 25
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        address: ["10.0.0.2/32", "fd00::2/128"],
        mtu: 1420,
        remoteDNS: ["1.1.1.1", "8.8.8.8"]
      }
    },
    expectedWarnings: []
  },
  {
    name: "Config with inline comments and quotes and Reserved in Interface",
    conf: `
# This is a comment
; Another comment
[Interface]
PrivateKey = "cccccccc33333333cccccccc33333333cccccccc33=" # secret key
Address = 172.16.0.2/24   ; internal IP
Reserved = [1, 2, 3] # reserved bytes
MTU = 1380

[Peer]
PublicKey = 'dddddddd44444444dddddddd44444444dddddddd44='
Endpoint = example.com:51820 # endpoint
PresharedKey = pskpskpskpskpskpskpskpskpskpskpskpskpsk=
AllowedIPs = 10.0.0.0/8, 192.168.0.0/16
PersistentKeepalive = 15
`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "cccccccc33333333cccccccc33333333cccccccc33=",
        peers: [
          {
            publicKey: "dddddddd44444444dddddddd44444444dddddddd44=",
            endpoint: "example.com:51820",
            allowedIPs: ["10.0.0.0/8", "192.168.0.0/16"],
            preSharedKey: "pskpskpskpskpskpskpskpskpskpskpskpskpsk=",
            keepAlive: 15
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        address: ["172.16.0.2/24"],
        mtu: 1380,
        reserved: [1, 2, 3]
      }
    },
    expectedWarnings: []
  },
  {
    name: "Config with Reserved in Peer and multiple peers",
    conf: `
[Interface]
PrivateKey = eeeeeeee55555555eeeeeeee55555555eeeeeeee55=

[Peer]
PublicKey = ffffffff66666666ffffffff66666666ffffffff66=
Endpoint = 1.2.3.4:51820
Reserved = 10, 20, 30

[Peer]
PublicKey = 111111117777777711111111777777771111111177=
Endpoint = 5.6.7.8:51820
`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "eeeeeeee55555555eeeeeeee55555555eeeeeeee55=",
        peers: [
          {
            publicKey: "ffffffff66666666ffffffff66666666ffffffff66=",
            endpoint: "1.2.3.4:51820"
          },
          {
            publicKey: "111111117777777711111111777777771111111177=",
            endpoint: "5.6.7.8:51820"
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        reserved: [10, 20, 30]
      }
    },
    expectedWarnings: [
      "Address not found in [Interface]; Xray will use its default value.",
      "Reserved was read from [Peer] and moved to outbound-level settings."
    ]
  },
  {
    name: "Unknown sections and ignored lines",
    conf: `
IgnoredLineWithoutEqualSign
[Interface]
PrivateKey = gggggggg88888888gggggggg88888888gggggggg88=
Address = 10.66.66.2/32

[CustomSection]
Foo = Bar

[Peer]
PublicKey = hhhhhhhh99999999hhhhhhhh99999999hhhhhhhh99=
Endpoint = 9.9.9.9:51820
`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "gggggggg88888888gggggggg88888888gggggggg88=",
        peers: [
          {
            publicKey: "hhhhhhhh99999999hhhhhhhh99999999hhhhhhhh99=",
            endpoint: "9.9.9.9:51820"
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        address: ["10.66.66.2/32"]
      }
    },
    expectedWarnings: [
      "Line 2 could not be read and was ignored: IgnoredLineWithoutEqualSign",
      "Section [customsection] on line 7 was ignored.",
      "Key outside valid section on line 8 was ignored: Foo"
    ]
  },
  {
    name: "Reserved with multiple zeros: 0, 00, 0",
    conf: `[Interface]\nPrivateKey = secret11111111secret11111111secret11111111se=\nReserved = 0, 00, 0\n[Peer]\nPublicKey = pub11111111pub11111111pub11111111pub11111111pu=\nEndpoint = 1.1.1.1:51820`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "secret11111111secret11111111secret11111111se=",
        peers: [
          {
            publicKey: "pub11111111pub11111111pub11111111pub11111111pu=",
            endpoint: "1.1.1.1:51820"
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        reserved: [0, 0, 0]
      }
    },
    expectedWarnings: [
      "Address not found in [Interface]; Xray will use its default value."
    ]
  },
  {
    name: "Reserved with boundary bracket variations",
    conf: `[Interface]\nPrivateKey = secret22222222secret22222222secret22222222se=\nReserved = 1, 2, 3]\n[Peer]\nPublicKey = pub22222222pub22222222pub22222222pub22222222pu=\nEndpoint = 2.2.2.2:51820`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "secret22222222secret22222222secret22222222se=",
        peers: [
          {
            publicKey: "pub22222222pub22222222pub22222222pub22222222pu=",
            endpoint: "2.2.2.2:51820"
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        reserved: [1, 2, 3]
      }
    },
    expectedWarnings: [
      "Address not found in [Interface]; Xray will use its default value."
    ]
  },
  {
    name: "Reserved with hex and signs",
    conf: `[Interface]\nPrivateKey = secret33333333secret33333333secret33333333se=\nReserved = +0x10, 0x20, 0x30\n[Peer]\nPublicKey = pub33333333pub33333333pub33333333pub33333333pu=\nEndpoint = 3.3.3.3:51820`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "secret33333333secret33333333secret33333333se=",
        peers: [
          {
            publicKey: "pub33333333pub33333333pub33333333pub33333333pu=",
            endpoint: "3.3.3.3:51820"
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        reserved: [16, 32, 48]
      }
    },
    expectedWarnings: [
      "Address not found in [Interface]; Xray will use its default value."
    ]
  },
  {
    name: "CR-only line endings (classic Mac)",
    conf: "[Interface]\rPrivateKey = secret44444444secret44444444secret44444444se=\rAddress = 10.0.0.4/32\r[Peer]\rPublicKey = pub44444444pub44444444pub44444444pub44444444pu=\rEndpoint = 4.4.4.4:51820\r",
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "secret44444444secret44444444secret44444444se=",
        peers: [
          {
            publicKey: "pub44444444pub44444444pub44444444pub44444444pu=",
            endpoint: "4.4.4.4:51820"
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        address: ["10.0.0.4/32"]
      }
    },
    expectedWarnings: []
  },
  {
    name: "Repeated Address, DNS, AllowedIPs and base64 reserved",
    conf: `[Interface]
PrivateKey = aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11=
Address = 10.0.0.2/32
Address = fd00::2/128
DNS = 1.1.1.1
DNS = 8.8.8.8
Reserved = AAAA
[Peer]
PublicKey = bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11=",
        peers: [
          {
            publicKey: "bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22=",
            endpoint: "198.51.100.1:51820",
            allowedIPs: ["0.0.0.0/0", "::/0"]
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        address: ["10.0.0.2/32", "fd00::2/128"],
        remoteDNS: ["1.1.1.1", "8.8.8.8"],
        reserved: [0, 0, 0]
      }
    },
    expectedWarnings: []
  },
  {
    name: "Aliases (SecretKey, Pubkey, Keepalive) and no MTU",
    conf: `[Interface]
SecretKey = cccccccc33333333cccccccc33333333cccccccc33=
LocalAddress = 192.168.1.5/24
[Peer]
Pubkey = dddddddd44444444dddddddd44444444dddddddd44=
Server = vpn.example.com:51820
Keepalive = 30`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "cccccccc33333333cccccccc33333333cccccccc33=",
        peers: [
          {
            publicKey: "dddddddd44444444dddddddd44444444dddddddd44=",
            endpoint: "vpn.example.com:51820",
            keepAlive: 30
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        address: ["192.168.1.5/24"]
      }
    },
    expectedWarnings: []
  },
  {
    name: "Base64URL reserved and space-separated parameters",
    conf: `[Interface]
private_key = aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11=
Address = 10.0.0.2/32 fd00::2/128
DNS = 1.1.1.1 8.8.8.8
Reserved = a-b_
[Peer]
public-key = bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22=
Endpoint = 198.51.100.1:51820
allowed_ips = 0.0.0.0/0 ::/0
persistent-keepalive = 20`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11=",
        peers: [
          {
            publicKey: "bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22=",
            endpoint: "198.51.100.1:51820",
            allowedIPs: ["0.0.0.0/0", "::/0"],
            keepAlive: 20
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        address: ["10.0.0.2/32", "fd00::2/128"],
        remoteDNS: ["1.1.1.1", "8.8.8.8"],
        reserved: [107, 230, 255]
      }
    },
    expectedWarnings: []
  },
  {
    name: "Quoted reserved, mixed aliases, and multiple lines",
    conf: `[Interface]
Secret_Key = cccccccc33333333cccccccc33333333cccccccc33=
Address = 10.0.0.2/32
IP = fd00::2/128
LocalAddress = 192.168.1.1/24
DNS = 1.1.1.1
NameServer = 8.8.8.8
Reserved = "1, 2, 3"
ListenPort = 51820
[Peer]
Peer_Public_Key = dddddddd44444444dddddddd44444444dddddddd44=
Remote = vpn.example.com:51820
PresharedKey = pskpskpskpskpskpskpskpskpskpskpskpskpsk=
AllowedIPs = 10.0.0.0/8
Allowed = 192.168.0.0/16
Routing = 172.16.0.0/12
Keep_Alive = 15`,
    expectedConfig: {
      tag: "wireguard",
      protocol: "wireguard",
      settings: {
        secretKey: "cccccccc33333333cccccccc33333333cccccccc33=",
        peers: [
          {
            publicKey: "dddddddd44444444dddddddd44444444dddddddd44=",
            endpoint: "vpn.example.com:51820",
            allowedIPs: ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
            preSharedKey: "pskpskpskpskpskpskpskpskpskpskpskpskpsk=",
            keepAlive: 15
          }
        ],
        noKernelTun: true,
        domainStrategy: "ForceIP",
        address: ["10.0.0.2/32", "fd00::2/128", "192.168.1.1/24"],
        remoteDNS: ["1.1.1.1", "8.8.8.8"],
        reserved: [1, 2, 3]
      }
    },
    expectedWarnings: []
  }
];

let allPassed = true;

console.log("Testing Core Configurations (12 cases):");
for (const tc of testCases) {
  process.stdout.write(`  • Testing: ${tc.name}... `);

  const jsParsed = converter.parseWireguardConfig(tc.conf);
  const jsBuilt = converter.buildXrayConfig(jsParsed, {
    tag: "wireguard",
    domainStrategy: "ForceIP",
    mtuOverride: null,
    noKernelTun: true,
    wrapInOutbounds: false
  });

  try {
    assert.deepStrictEqual(jsBuilt.config, tc.expectedConfig);
    assert.deepStrictEqual(jsBuilt.warnings, tc.expectedWarnings);
    console.log("✅ Passed");
  } catch (err) {
    console.log("❌ Failed");
    console.error(err.message);
    allPassed = false;
  }
}

// Test error handling
const errorCases = [
  {
    name: "Missing PrivateKey",
    conf: `[Interface]\nAddress = 10.0.0.1\n[Peer]\nPublicKey = abc\nEndpoint = 1.2.3.4:51820`,
    expectedError: "PrivateKey not found in [Interface] section."
  },
  {
    name: "Missing Peer",
    conf: `[Interface]\nPrivateKey = secret`,
    expectedError: "No [Peer] section found in WireGuard file."
  },
  {
    name: "Missing PublicKey in Peer",
    conf: `[Interface]\nPrivateKey = secret\n[Peer]\nEndpoint = 1.2.3.4:51820`,
    expectedError: "PublicKey not found in Peer number 1."
  },
  {
    name: "Missing Endpoint in Peer",
    conf: `[Interface]\nPrivateKey = secret\n[Peer]\nPublicKey = pubkey`,
    expectedError: "Endpoint not found in Peer number 1."
  },
  {
    name: "Invalid Reserved count",
    conf: `[Interface]\nPrivateKey = secret\nReserved = 1, 2\n[Peer]\nPublicKey = pubkey\nEndpoint = 1.2.3.4:51820`,
    expectedError: "Reserved must contain exactly 3 numbers"
  },
  {
    name: "Invalid Reserved out of bounds",
    conf: `[Interface]\nPrivateKey = secret\nReserved = 1, 256, 3\n[Peer]\nPublicKey = pubkey\nEndpoint = 1.2.3.4:51820`,
    expectedError: "Reserved values must be between 0 and 255"
  },
  {
    name: "Invalid Reserved leading zero decimal",
    conf: `[Interface]\nPrivateKey = secret\nReserved = 01, 2, 3\n[Peer]\nPublicKey = pubkey\nEndpoint = 1.2.3.4:51820`,
    expectedError: "Invalid Reserved"
  },
  {
    name: "Invalid MTU range",
    conf: `[Interface]\nPrivateKey = secret\nMTU = 500\n[Peer]\nPublicKey = pubkey\nEndpoint = 1.2.3.4:51820`,
    expectedError: "MTU should normally be between 576 and 9000"
  },
  {
    name: "Negative PersistentKeepalive",
    conf: `[Interface]\nPrivateKey = secret\n[Peer]\nPublicKey = pubkey\nEndpoint = 1.2.3.4:51820\nPersistentKeepalive = -1`,
    expectedError: "PersistentKeepalive cannot be negative"
  }
];

console.log("\nTesting Error Handling (9 cases):");
for (const ec of errorCases) {
  process.stdout.write(`  • Testing error: '${ec.name}'... `);
  try {
    const parsed = converter.parseWireguardConfig(ec.conf);
    converter.buildXrayConfig(parsed, {
      mtuOverride: parsed.interface.mtu || "1420"
    });
    console.log("❌ Failed (no error thrown)");
    allPassed = false;
  } catch (err) {
    if (err.message.includes(ec.expectedError)) {
      console.log("✅ Caught expected error");
    } else {
      console.log(`❌ Error mismatch: got "${err.message}", expected "${ec.expectedError}"`);
      allPassed = false;
    }
  }
}

// Test WireGuard URI generation
console.log("\nTesting WireGuard URI Generation:");
const userConf = `[Interface]
PrivateKey = 8Mn46OZH7DTRrHPAejXiGZ1Ide/GCBawNt6NDHJpfU8=
Address = 10.0.0.2/32
MTU = 1420

[Peer]
PublicKey = bwanSi8gvcFJkSBbC5K0ED/gZ7r8tNq8Twp3YqOigEQ=
Endpoint = vip.jojo-data.com:46341
`;

const parsedUser = converter.parseWireguardConfig(userConf);
const uris = converter.buildWireguardUri(parsedUser, { tag: "owner" });
const expectedUri = "wireguard://8Mn46OZH7DTRrHPAejXiGZ1Ide%2FGCBawNt6NDHJpfU8%3D@vip.jojo-data.com:46341?address=10.0.0.2%2F32&mtu=1420&publickey=bwanSi8gvcFJkSBbC5K0ED%2FgZ7r8tNq8Twp3YqOigEQ%3D#owner";

if (uris[0] === expectedUri) {
  console.log("  ✅ User example URI matched exactly!");
} else {
  console.error("  ❌ User example URI mismatch!");
  console.error("  Got:     ", uris[0]);
  console.error("  Expected:", expectedUri);
  allPassed = false;
}

// Test URI generation without MTU and without keepalive
console.log("\nTesting URI Generation without extra settings (MTU, keepalive):");
const minimalConf = `[Interface]
PrivateKey = 8Mn46OZH7DTRrHPAejXiGZ1Ide/GCBawNt6NDHJpfU8=
Address = 10.0.0.2/32

[Peer]
PublicKey = bwanSi8gvcFJkSBbC5K0ED/gZ7r8tNq8Twp3YqOigEQ=
Endpoint = vip.jojo-data.com:46341
`;
const parsedMinimal = converter.parseWireguardConfig(minimalConf);
const minimalUris = converter.buildWireguardUri(parsedMinimal, { tag: "germany" });
const minimalXray = converter.buildXrayConfig(parsedMinimal, { tag: "germany", wrapInOutbounds: false });

if (minimalUris[0].includes("mtu=")) {
  console.error("  ❌ URI should NOT contain mtu when not in config!");
  allPassed = false;
} else if (minimalUris[0].includes("keepalive=")) {
  console.error("  ❌ URI should NOT contain keepalive when not in config!");
  allPassed = false;
} else if (!minimalUris[0].endsWith("#germany")) {
  console.error("  ❌ URI tag should match 'germany'!");
  allPassed = false;
} else {
  console.log("  ✅ URI correctly omits mtu and keepalive, and uses filename tag!");
}

if ("mtu" in minimalXray.config.settings) {
  console.error("  ❌ Xray config should NOT contain mtu when not in config!");
  allPassed = false;
} else if ("keepAlive" in minimalXray.config.settings.peers[0]) {
  console.error("  ❌ Xray peer should NOT contain keepAlive when not in config!");
  allPassed = false;
} else {
  console.log("  ✅ Xray JSON correctly omits mtu and keepAlive when not in config!");
}

if (!allPassed) {
  process.exit(1);
}
console.log("\n✅ ALL CONVERTER TESTS PASSED SUCCESSFULLY! (Pure JavaScript, 0% Python)");
