const fs = require("fs");
const vm = require("vm");

const html = fs.readFileSync("index.html", "utf-8");

// Verify requirement 1: Sample button and its config content are completely removed
console.log("Testing Removal of Sample Button and Sample Config:");
if (html.includes('id="loadSampleBtn"') || html.includes("SAMPLE_CONFIG") || html.includes("vip.jojo-data.com:46341")) {
  console.error("❌ Sample button or sample config still present in index.html!");
  process.exit(1);
}
console.log("  ✅ Sample button and sample config are completely removed from index.html!");

// Verify requirement 3: optMtu input is removed from UI
if (html.includes('id="optMtu"')) {
  console.error("❌ optMtu input is still present in index.html!");
  process.exit(1);
}
console.log("  ✅ optMtu input is completely removed from index.html!");

// Extract script content
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/i);
if (!scriptMatch) {
  console.error("❌ No script tag found in index.html!");
  process.exit(1);
}

const scriptCode = scriptMatch[1];

// Create mock DOM elements
const mockElements = {};
function createMockElement(id) {
  return {
    id,
    value: id === "optDomain" ? "ForceIP" : "",
    checked: id === "optNoKernelTun",
    textContent: "",
    innerHTML: "",
    placeholder: "",
    style: {},
    classList: {
      add: () => {},
      remove: () => {}
    },
    addEventListener: (event, handler) => {
      mockElements[`${id}_${event}`] = handler;
    },
    click: () => {},
    setAttribute: () => {},
    getAttribute: () => "",
  };
}

const elementIds = [
  "dropzone", "fileInput", "selectFileBtn", "loadedFileBadge", "loadedFileName", "removeFileBtn",
  "configText", "charCount", "clearInputBtn", "convertBtn",
  "optTag", "optDomain", "optNoKernelTun", "optWrapOutbounds",
  "viewAllBtn", "viewUriBtn", "viewJsonBtn", "sectionUri", "sectionJson",
  "outputUriPre", "copyUriBtn",
  "outputJsonPre", "copyJsonBtn", "downloadJsonBtn",
  "messagesList", "toast", "toastText"
];

const elements = {};
elementIds.forEach(id => {
  elements[id] = createMockElement(id);
});

// Create a sandbox to run the converter functions
const sandbox = {
  console: console,
  document: {
    documentElement: { lang: "en" },
    querySelectorAll: () => [],
    getElementById: (id) => elements[id] || createMockElement(id),
    createElement: () => ({ style: {}, appendChild: () => {}, select: () => {} }),
    body: { appendChild: () => {}, removeChild: () => {} },
  },
  navigator: { clipboard: { writeText: async () => {} } },
  URL: { createObjectURL: () => "blob:fake-url", revokeObjectURL: () => {} },
  FileReader: class {
    readAsText(file) {
      if (this.onload) {
        this.onload({ target: { result: file.content || "" } });
      }
    }
  },
  setTimeout: (fn) => fn(),
};

vm.createContext(sandbox);
vm.runInContext(scriptCode, sandbox);

console.log("Script evaluated successfully in sandbox.");

// 1. Test XSS sanitization
console.log("\nTesting XSS prevention:");
const sanitized = sandbox.escapeHtml("<script>alert('xss')</script>&\"test'");
if (sanitized.includes("<script>") || sanitized.includes("'xss'")) {
  console.error("❌ escapeHtml failed to sanitize HTML entities!");
  process.exit(1);
}
console.log("  ✅ escapeHtml sanitizes properly:", sanitized);

sandbox.showError("<script>alert(1)</script>");
if (elements["messagesList"].innerHTML.includes("<script>")) {
  console.error("❌ showError allowed raw unescaped HTML injection!");
  process.exit(1);
}
console.log("  ✅ showError safely escapes error message!");

sandbox.renderSuccess("<img src=x onerror=alert(1)>", { peers: [], interface: { privatekey: "k" } }, ["<script>warning</script>"], 1);
if (elements["messagesList"].innerHTML.includes("<img src=x") || elements["messagesList"].innerHTML.includes("<script>")) {
  console.error("❌ renderSuccess allowed raw unescaped HTML injection!");
  process.exit(1);
}
console.log("  ✅ renderSuccess safely escapes filenames and warnings!");

// 2. Test WireGuard Tag auto-selection from file name
console.log("\nTesting Tag Auto-Selection from File Name (Requirement 2):");
const mockFile = {
  name: "Germany-Frankfurt.conf",
  content: `[Interface]
PrivateKey = aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11=
Address = 10.0.0.2/32
[Peer]
PublicKey = bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22=
Endpoint = 198.51.100.1:51820`
};

sandbox.handleFile(mockFile);

if (elements["optTag"].value !== "Germany-Frankfurt") {
  console.error(`❌ optTag was not set to file base name! Got "${elements["optTag"].value}", expected "Germany-Frankfurt"`);
  process.exit(1);
}
console.log("  ✅ handleFile automatically populates optTag from filename (Germany-Frankfurt)!");

if (!elements["outputJsonPre"].innerHTML.includes("Germany-Frankfurt")) {
  console.error("❌ Output JSON does not contain tag 'Germany-Frankfurt'!");
  process.exit(1);
}
console.log("  ✅ Generated output JSON tag matches filename!");

if (!elements["outputUriPre"].textContent.includes("#Germany-Frankfurt")) {
  console.error("❌ Output URI does not contain tag '#Germany-Frankfurt'!");
  process.exit(1);
}
console.log("  ✅ Generated WireGuard URI tag matches filename (#Germany-Frankfurt)!");

// 3. Test Extra Settings Omission (Requirement 3: MTU & Keepalive only when in config)
console.log("\nTesting Extra Settings Omission (Requirement 3):");
// File mockFile had NO MTU and NO keepalive
if (elements["outputJsonPre"].innerHTML.includes("mtu")) {
  console.error("❌ Converted JSON contains mtu even though config had no MTU!");
  process.exit(1);
}
if (elements["outputJsonPre"].innerHTML.includes("keepAlive")) {
  console.error("❌ Converted JSON contains keepAlive even though config had no PersistentKeepalive!");
  process.exit(1);
}
if (elements["outputUriPre"].textContent.includes("mtu=")) {
  console.error("❌ Converted URI contains mtu= even though config had no MTU!");
  process.exit(1);
}
if (elements["outputUriPre"].textContent.includes("keepalive=")) {
  console.error("❌ Converted URI contains keepalive= even though config had no PersistentKeepalive!");
  process.exit(1);
}
console.log("  ✅ Converted output omits mtu and keepalive when absent from original config!");

// Now test WITH MTU and keepalive in config
elements["configText"].value = `[Interface]
PrivateKey = aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11=
Address = 10.0.0.2/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1380
[Peer]
PublicKey = bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22=
Endpoint = 198.51.100.1:51820
PersistentKeepalive = 25`;

sandbox.doConvert("custom-vpn.conf");

if (!elements["outputJsonPre"].innerHTML.includes("1380")) {
  console.error("❌ MTU 1380 missing from converted JSON when present in config!");
  process.exit(1);
}
if (!elements["outputJsonPre"].innerHTML.includes("remoteDNS")) {
  console.error("❌ remoteDNS missing from converted JSON when DNS is in config!");
  process.exit(1);
}
if (!elements["outputJsonPre"].innerHTML.includes("keepAlive") || !elements["outputJsonPre"].innerHTML.includes("25")) {
  console.error("❌ keepAlive missing from converted JSON when PersistentKeepalive is in config!");
  process.exit(1);
}
if (!elements["outputUriPre"].textContent.includes("mtu=1380")) {
  console.error("❌ mtu=1380 missing from URI when present in config!");
  process.exit(1);
}
if (!elements["outputUriPre"].textContent.includes("keepalive=25")) {
  console.error("❌ keepalive=25 missing from URI when present in config!");
  process.exit(1);
}
if (!elements["outputUriPre"].textContent.includes("dns=1.1.1.1%2C8.8.8.8")) {
  console.error("❌ dns missing from URI when present in config!");
  process.exit(1);
}
console.log("  ✅ When present in original config, MTU (1380), DNS, and keepalive (25) are included properly!");

// 4. Test View Filter Switching
console.log("\nTesting View Filter Modes:");
sandbox.setViewMode("uri");
if (elements["sectionUri"].style.display !== "flex" || elements["sectionJson"].style.display !== "none") {
  console.error("❌ setViewMode('uri') did not toggle sections correctly!");
  process.exit(1);
}
console.log("  ✅ setViewMode('uri') shows URI section and hides JSON section");

sandbox.setViewMode("json");
if (elements["sectionUri"].style.display !== "none" || elements["sectionJson"].style.display !== "flex") {
  console.error("❌ setViewMode('json') did not toggle sections correctly!");
  process.exit(1);
}
console.log("  ✅ setViewMode('json') shows JSON section and hides URI section");

sandbox.setViewMode("all");
if (elements["sectionUri"].style.display !== "flex" || elements["sectionJson"].style.display !== "flex") {
  console.error("❌ setViewMode('all') did not show both sections!");
  process.exit(1);
}
console.log("  ✅ setViewMode('all') displays both URI and JSON sections");

// 5. Test file picker reset
console.log("\nTesting File Picker Reset:");
elements["fileInput"].value = "C:\\fakepath\\test.conf";
sandbox.openFilePicker();
if (elements["fileInput"].value !== "") {
  console.error("❌ openFilePicker failed to clear fileInput.value!");
  process.exit(1);
}
console.log("  ✅ openFilePicker clears fileInput.value to ensure re-selecting same file fires change event!");

console.log("\n✅ ALL ADVANCED index.html VALIDATION CHECKS PASSED!");
