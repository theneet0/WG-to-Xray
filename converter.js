// WireGuard -> Xray WireGuard Outbound Converter Core Logic
// Compatible with Xray-core 26.x / 26.6.1

const VALID_DOMAIN_STRATEGIES = [
  "ForceIP",
  "ForceIPv4",
  "ForceIPv6",
  "ForceIPv4v6",
  "ForceIPv6v4",
];

function normalizeKey(key) {
  return key.trim().toLowerCase().replace(/\s+/g, "");
}

function stripInlineComment(value) {
  let v = value.trim();
  const match = v.search(/\s+[;#]/);
  if (match !== -1) {
    v = v.slice(0, match).trim();
  }
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    v = v.slice(1, -1).trim();
  }
  return v;
}

function splitCsv(value) {
  if (!value) return [];
  return value.split(",").map(item => item.trim()).filter(Boolean);
}

function parseIntegerBase(part) {
  const trimmed = part.trim();
  if (!trimmed) return NaN;
  let sign = 1;
  let s = trimmed;
  if (s.startsWith("+")) {
    s = s.slice(1);
  } else if (s.startsWith("-")) {
    sign = -1;
    s = s.slice(1);
  }
  if (!s) return NaN;
  if (/^0x[0-9a-f]+$/i.test(s)) {
    return sign * parseInt(s.slice(2), 16);
  }
  if (/^0o[0-7]+$/i.test(s)) {
    return sign * parseInt(s.slice(2), 8);
  }
  if (/^0b[01]+$/i.test(s)) {
    return sign * parseInt(s.slice(2), 2);
  }
  if (/^0+$/.test(s)) {
    return 0;
  }
  if (/^[1-9]\d*$/.test(s)) {
    return sign * parseInt(s, 10);
  }
  return NaN;
}

function parseReserved(value) {
  let clean = value.trim().replace(/^[\[\]]+|[\[\]]+$/g, "").trim();
  if (!clean) return [];

  // Support 4-char base64 representation of 3 bytes (e.g. WARP reserved bytes)
  if (/^[A-Za-z0-9+/]{4}={0,2}$/.test(clean)) {
    try {
      let bytes = [];
      if (typeof Buffer !== "undefined") {
        bytes = Array.from(Buffer.from(clean, "base64"));
      } else if (typeof atob !== "undefined") {
        const binStr = atob(clean);
        for (let i = 0; i < binStr.length; i++) {
          bytes.push(binStr.charCodeAt(i));
        }
      }
      if (bytes.length === 3) {
        return bytes;
      }
    } catch (_) {}
  }

  const parts = clean.split(/[,\s]+/).filter(Boolean);
  const nums = [];
  for (const part of parts) {
    const num = parseIntegerBase(part);
    if (isNaN(num)) {
      throw new Error(`Invalid Reserved: ${value}`);
    }
    if (num < 0 || num > 255) {
      throw new Error(`Reserved values must be between 0 and 255: ${value}`);
    }
    nums.push(num);
  }
  if (nums.length !== 3) {
    throw new Error(`Reserved must contain exactly 3 numbers, found ${nums.length}. Value: ${value}`);
  }
  return nums;
}

function parseKeepalive(value) {
  const trimmed = value.trim();
  if (!/^[+-]?\d+$/.test(trimmed)) {
    throw new Error(`Invalid PersistentKeepalive: ${value}`);
  }
  const keepalive = parseInt(trimmed, 10);
  if (keepalive < 0) {
    throw new Error("PersistentKeepalive cannot be negative");
  }
  return keepalive;
}

function parseMtu(value) {
  const trimmed = value.trim();
  if (!/^[+-]?\d+$/.test(trimmed)) {
    throw new Error(`Invalid MTU: ${value}`);
  }
  const mtu = parseInt(trimmed, 10);
  if (mtu < 576 || mtu > 9000) {
    throw new Error("MTU should normally be between 576 and 9000");
  }
  return mtu;
}

function parseWireguardConfig(text) {
  const result = {
    interface: {},
    peers: [],
    warnings: [],
  };
  let currentSection = null;
  let currentPeer = null;

  // Strip UTF-8 BOM if present
  const cleanText = text.replace(/^\uFEFF/, "");
  const lines = cleanText.split(/\r\n|\r|\n/);

  const listKeys = ["address", "dns", "allowedips"];

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const rawLine = lines[i];
    const line = rawLine.trim();

    if (!line || line.startsWith("#") || line.startsWith(";")) {
      continue;
    }

    const sectionMatch = line.match(/^\[(.+?)\]$/);
    if (sectionMatch) {
      const section = sectionMatch[1].trim().toLowerCase();
      currentSection = section;
      if (section === "interface") {
        currentPeer = null;
      } else if (section === "peer") {
        currentPeer = {};
        result.peers.push(currentPeer);
      } else {
        currentPeer = null;
        result.warnings.push(`Section [${section}] on line ${lineNo} was ignored.`);
      }
      continue;
    }

    const eqIdx = line.indexOf("=");
    if (eqIdx === -1) {
      result.warnings.push(`Line ${lineNo} could not be read and was ignored: ${rawLine}`);
      continue;
    }

    const key = line.slice(0, eqIdx);
    const value = line.slice(eqIdx + 1);
    const keyNorm = normalizeKey(key);
    const valueClean = stripInlineComment(value);

    if (currentSection === "interface") {
      if (listKeys.includes(keyNorm) && result.interface[keyNorm]) {
        result.interface[keyNorm] += ", " + valueClean;
      } else {
        result.interface[keyNorm] = valueClean;
      }
    } else if (currentSection === "peer" && currentPeer !== null) {
      if (listKeys.includes(keyNorm) && currentPeer[keyNorm]) {
        currentPeer[keyNorm] += ", " + valueClean;
      } else {
        currentPeer[keyNorm] = valueClean;
      }
    } else {
      result.warnings.push(`Key outside valid section on line ${lineNo} was ignored: ${key.trim()}`);
    }
  }

  return result;
}

function buildXrayConfig(parsed, options = {}) {
  const {
    tag = "wireguard",
    domainStrategy = "ForceIP",
    mtuOverride = null,
    noKernelTun = false,
    wrapInOutbounds = true,
  } = options;

  const warnings = [...parsed.warnings];
  const iface = parsed.interface || {};
  const peers = parsed.peers || [];

  const privateKey = (iface.privatekey || iface.secretkey || iface.privkey || "").trim();
  if (!privateKey) {
    throw new Error("PrivateKey not found in [Interface] section.");
  }

  if (peers.length === 0) {
    throw new Error("No [Peer] section found in WireGuard file.");
  }

  const settings = {
    secretKey: privateKey,
    peers: [],
    noKernelTun: Boolean(noKernelTun),
    domainStrategy: VALID_DOMAIN_STRATEGIES.includes(domainStrategy) ? domainStrategy : "ForceIP",
  };

  const addresses = splitCsv(iface.address || iface.ip || iface.localaddress || iface.localip || iface.addresses || "");
  if (addresses.length > 0) {
    settings.address = addresses;
  } else {
    warnings.push("Address not found in [Interface]; Xray will use its default value.");
  }

  // MTU: Only included when present in original config (or explicit override)
  const mtuSource = (mtuOverride && String(mtuOverride).trim()) ? String(mtuOverride).trim() : (iface.mtu || "").trim();
  if (mtuSource) {
    settings.mtu = parseMtu(mtuSource);
  }

  // DNS: Transferred to remoteDNS in Xray WireGuard outbound
  const dnsList = splitCsv(iface.dns || iface.remotedns || iface.dnsserver || iface.nameserver || "");
  if (dnsList.length > 0) {
    settings.remoteDNS = dnsList;
  }

  let reservedText = iface.reserved || "";
  if (!reservedText) {
    for (const peer of peers) {
      if (peer.reserved) {
        reservedText = peer.reserved;
        warnings.push("Reserved was read from [Peer] and moved to outbound-level settings.");
        break;
      }
    }
  }
  if (reservedText) {
    settings.reserved = parseReserved(reservedText);
  }

  const xrayPeers = [];
  for (let i = 0; i < peers.length; i++) {
    const peer = peers[i];
    const index = i + 1;
    const publicKey = (peer.publickey || peer.pubkey || peer.peerpublickey || "").trim();
    const endpoint = (peer.endpoint || peer.server || peer.peerendpoint || "").trim();

    if (!publicKey) {
      throw new Error(`PublicKey not found in Peer number ${index}.`);
    }
    if (!endpoint) {
      throw new Error(`Endpoint not found in Peer number ${index}.`);
    }

    const xrayPeer = {
      publicKey,
      endpoint,
    };

    const allowedIps = splitCsv(peer.allowedips || peer.allowed_ips || peer.allowed || "");
    if (allowedIps.length > 0) {
      xrayPeer.allowedIPs = allowedIps;
    }

    const psk = (peer.presharedkey || peer.pre_shared_key || peer.psk || "").trim();
    if (psk) {
      xrayPeer.preSharedKey = psk;
    }

    // PersistentKeepalive: Only included when present in original config
    const keepaliveText = (peer.persistentkeepalive || peer.persistent_keepalive || peer.keepalive || "").trim();
    if (keepaliveText) {
      xrayPeer.keepAlive = parseKeepalive(keepaliveText);
    }

    xrayPeers.push(xrayPeer);
  }

  settings.peers = xrayPeers;

  const outbound = {
    tag: (tag && tag.trim()) ? tag.trim() : "wireguard",
    protocol: "wireguard",
    settings,
  };

  if (wrapInOutbounds) {
    return { config: { outbounds: [outbound] }, warnings };
  }
  return { config: outbound, warnings };
}

function buildWireguardUri(parsed, options = {}) {
  const {
    tag = "wireguard",
    mtuOverride = null,
  } = options;

  const iface = parsed.interface || {};
  const peers = parsed.peers || [];

  const privateKey = (iface.privatekey || iface.secretkey || iface.privkey || "").trim();
  if (!privateKey) {
    throw new Error("PrivateKey not found in [Interface] section.");
  }
  if (peers.length === 0) {
    throw new Error("No [Peer] section found in WireGuard file.");
  }

  const addresses = splitCsv(iface.address || iface.ip || iface.localaddress || iface.localip || iface.addresses || "");
  const dnsList = splitCsv(iface.dns || iface.remotedns || iface.dnsserver || iface.nameserver || "");

  // MTU: Only included when present in original config (or explicit override)
  const mtuSource = (mtuOverride && String(mtuOverride).trim()) ? String(mtuOverride).trim() : (iface.mtu || "").trim();
  let mtuValue = null;
  if (mtuSource) {
    mtuValue = parseMtu(mtuSource);
  }

  let reservedText = iface.reserved || "";
  if (!reservedText) {
    for (const peer of peers) {
      if (peer.reserved) {
        reservedText = peer.reserved;
        break;
      }
    }
  }
  let reservedNums = [];
  if (reservedText) {
    reservedNums = parseReserved(reservedText);
  }

  const uris = [];
  for (let i = 0; i < peers.length; i++) {
    const peer = peers[i];
    const index = i + 1;
    const publicKey = (peer.publickey || peer.pubkey || peer.peerpublickey || "").trim();
    const endpoint = (peer.endpoint || peer.server || peer.peerendpoint || "").trim();

    if (!publicKey) {
      throw new Error(`PublicKey not found in Peer number ${index}.`);
    }
    if (!endpoint) {
      throw new Error(`Endpoint not found in Peer number ${index}.`);
    }

    const encodedPrivKey = encodeURIComponent(privateKey);
    const queryParts = [];

    if (addresses.length > 0) {
      queryParts.push(`address=${encodeURIComponent(addresses.join(","))}`);
    }
    if (dnsList.length > 0) {
      queryParts.push(`dns=${encodeURIComponent(dnsList.join(","))}`);
    }
    if (mtuValue !== null) {
      queryParts.push(`mtu=${encodeURIComponent(mtuValue)}`);
    }
    queryParts.push(`publickey=${encodeURIComponent(publicKey)}`);

    const psk = (peer.presharedkey || peer.pre_shared_key || peer.psk || "").trim();
    if (psk) {
      queryParts.push(`presharedkey=${encodeURIComponent(psk)}`);
    }

    const allowedIps = splitCsv(peer.allowedips || peer.allowed_ips || peer.allowed || "");
    if (allowedIps.length > 0) {
      queryParts.push(`allowedips=${encodeURIComponent(allowedIps.join(","))}`);
    }

    if (reservedNums.length === 3) {
      queryParts.push(`reserved=${encodeURIComponent(reservedNums.join(","))}`);
    }

    const keepaliveText = (peer.persistentkeepalive || peer.persistent_keepalive || peer.keepalive || "").trim();
    if (keepaliveText) {
      queryParts.push(`keepalive=${encodeURIComponent(parseKeepalive(keepaliveText))}`);
    }

    const baseTag = (tag && tag.trim()) || "wireguard";
    const peerTag = peers.length > 1 ? `${baseTag}-${index}` : baseTag;
    const uri = `wireguard://${encodedPrivKey}@${endpoint}?${queryParts.join("&")}#${encodeURIComponent(peerTag)}`;
    uris.push(uri);
  }

  return uris;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    VALID_DOMAIN_STRATEGIES,
    normalizeKey,
    stripInlineComment,
    splitCsv,
    parseReserved,
    parseKeepalive,
    parseMtu,
    parseWireguardConfig,
    buildXrayConfig,
    buildWireguardUri,
  };
}

