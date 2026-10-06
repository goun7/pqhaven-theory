"""Data-logic tests for PQHaven cockpit UI functions not covered elsewhere.

These tests complement ``tests/test_cockpit_js.py`` by exercising the remaining
*data-processing* UI handlers of the Executive Cockpit's embedded script:

* ``renderCompliance``      — compliance-flag list rendering (incl. empty branch)
* ``openDrawer``/``closeDrawer`` — asset inspection drawer content & open state
* ``downloadCsv``           — CSV inventory export serialization
* ``downloadVc``            — W3C Verifiable Credential attestation export
* ``toggleGraphPhysics``    — physics toggle state & button label
* ``focusCriticalNodes``    — Shor-vulnerability quick filter

Canvas/DOM *rendering* (force-directed graph, histogram drawing) is deliberately
skipped; only the pure-data behaviour of the handlers is asserted.  The script
is extracted from :func:`pqhaven.cockpit.generate_cockpit_html` and executed in
Node against the same minimal DOM/clipboard mock used by the existing suite.
"""

import json
import re
import shutil
import subprocess

import pytest

from pqhaven.cockpit import generate_cockpit_html
from pqhaven.engine import PQScanEngine

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node runtime not available")

_SAMPLE_ASSETS = [
    {"name": "web-tls-cert", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048},
    {"name": "legacy-vpn-ike", "algorithm": "RSA-3072", "type": "protocol", "key_size": 3072},
    {"name": "api-kex", "algorithm": "ECDH-X25519", "type": "protocol", "key_size": 256},
    {"name": "mlkem-transport", "algorithm": "ML-KEM-768", "type": "key", "key_size": 768},
    {"name": "signing-service", "algorithm": "ML-DSA-44", "type": "algorithm", "key_size": 128},
]
_TARGET = "cockpit-js-test.internal"


def _build_report():
    return PQScanEngine().assess_target(_TARGET, _SAMPLE_ASSETS)


def _extract_script(html: str) -> str:
    start = html.index("<script>") + len("<script>")
    end = html.index("</script>")
    return html[start:end]


def _extract_chip_onclicks(html: str) -> list[str]:
    return re.findall(
        r'class="chip[^"]*"\s+onclick="(setFilterCategory\(\'\w+\', this\))"', html
    )


# --- Node harness: DOM / browser API mocks installed before the cockpit script ---
_HARNESS_PRE = r"""
var __results = {};
var __clipboard = [];
var __alerts = [];
var __blobs = [];
var __urls = [];
var __lastAnchor = null;
var __seed = 20260101;
var __chips = [];

function __resetSeed(s) { __seed = s >>> 0; }
Math.random = function () {
  __seed = (__seed * 1103515245 + 12345) & 0x7fffffff;
  return __seed / 0x7fffffff;
};

function __makeCtx() {
  var c = { fillStyle: "", strokeStyle: "", font: "12px sans-serif", lineWidth: 1,
            _fillRects: 0, _ops: [] };
  ["save", "restore", "scale", "translate", "rotate", "beginPath", "moveTo",
   "lineTo", "stroke", "fill", "strokeText", "fillText", "clearRect", "arc",
   "closePath", "drawImage", "createLinearGradient", "createRadialGradient"
  ].forEach(function (m) {
    c[m] = function () { c._ops.push(m); return undefined; };
  });
  c.fillRect = function () { c._fillRects++; c._ops.push("fillRect"); };
  c.setLineDash = function (d) { c._dash = d; };
  return c;
}

function __makeEl(tag) {
  var el = {
    tagName: tag, id: tag,
    __children: [], __html: "",
    innerText: "", textContent: "", value: "",
    style: {}, dataset: {},
    width: 0, height: 0, href: "", download: "",
    __onclick: "", __clicked: false,
    getAttribute: function (n) { return n === "onclick" ? el.__onclick : null; },
    setAttribute: function (n, v) { if (n === "onclick") { el.__onclick = String(v); } },
    appendChild: function (child) {
      el.__children.push(child);
      el.__html = el.__html + (child.__html !== undefined ? child.__html : "");
      return child;
    },
    removeChild: function (c) {
      var i = el.__children.indexOf(c);
      if (i >= 0) { el.__children.splice(i, 1); }
      return c;
    },
    addEventListener: function () { return undefined; },
    removeEventListener: function () { return undefined; },
    click: function () { el.__clicked = true; },
    focus: function () { return undefined; },
    remove: function () { return undefined; },
    getContext: function () { return el.__ctx || (el.__ctx = __makeCtx()); },
    getBoundingClientRect: function () {
      return { width: 900, height: 420, left: 0, top: 0, right: 900, bottom: 420 };
    }
  };
  Object.defineProperty(el, "innerHTML", {
    get: function () { return el.__html; },
    set: function (v) { el.__html = String(v); el.__children = []; }
  });
  var set = Object.create(null);
  el.classList = {
    add: function (c) { set[c] = true; },
    remove: function (c) { delete set[c]; },
    contains: function (c) { return set[c] === true; },
    toggle: function (c) { if (set[c]) { delete set[c]; } else { set[c] = true; } }
  };
  return el;
}

var __elCache = Object.create(null);
var __qCache = Object.create(null);
var document = {
  getElementById: function (id) { return __elCache[id] || (__elCache[id] = __makeEl(id)); },
  querySelector: function (sel) { return __qCache[sel] || (__qCache[sel] = __makeEl("q:" + sel)); },
  querySelectorAll: function (sel) {
    if (sel === ".chip") { return __chips; }
    return [];
  },
  createElement: function (tag) {
    var el = __makeEl(tag);
    if (tag === "a") { __lastAnchor = el; }
    return el;
  }
};

var window = {
  devicePixelRatio: 1, innerWidth: 1200, innerHeight: 800,
  addEventListener: function () { return undefined; },
  removeEventListener: function () { return undefined; },
  location: { href: "http://localhost/" }
};
var navigator = {
  userAgent: "node",
  clipboard: {
    writeText: function (t) { __clipboard.push(String(t)); return Promise.resolve(); }
  }
};
var alert = function (m) { __alerts.push(String(m)); };
var Blob = function (parts, opts) { this.parts = parts; this.opts = opts; __blobs.push(this); };
var URL = {
  createObjectURL: function (b) { __urls.push(b); return "blob:mock/" + __urls.length; },
  revokeObjectURL: function () { return undefined; }
};
var setTimeout = function () { return 0; };
var clearTimeout = function () { return undefined; };
var requestAnimationFrame = function () { return 0; };
var cancelAnimationFrame = function () { return undefined; };
var localStorage = {
  getItem: function () { return null; },
  setItem: function () { return undefined; },
  removeItem: function () { return undefined; }
};

__chips = __CHIPS_JSON__.map(function (oc) {
  var c = __makeEl("chip");
  c.setAttribute("onclick", oc);
  return c;
});
"""

_HARNESS_POST = r"""
__SCENARIO_BODY__
try {
  __scenario();
} catch (e) {
  __results.__error = String((e && e.stack) || e);
}
console.log("@@RESULTS@@" + JSON.stringify(__results));
"""


def _run_scenario(script: str, chips: list[str], scenario_body: str, tmp_path) -> dict:
    """Run the cockpit script + a scenario in Node and return the collected results."""
    harness = (
        _HARNESS_PRE.replace("__CHIPS_JSON__", json.dumps(chips))
        + "\n" + script + "\n"
        + _HARNESS_POST.replace("__SCENARIO_BODY__", scenario_body)
    )
    path = tmp_path / "cockpit_export_harness.js"
    path.write_text(harness, encoding="utf-8")
    proc = subprocess.run(
        [NODE, str(path)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, f"node harness failed (rc={proc.returncode}):\n{proc.stderr}"
    marker = "@@RESULTS@@"
    assert marker in proc.stdout, f"no results marker in stdout:\n{proc.stdout}\n{proc.stderr}"
    payload = proc.stdout[proc.stdout.index(marker) + len(marker):]
    payload = payload[payload.index("{"): payload.rindex("}") + 1]
    results = json.loads(payload)
    assert "__error" not in results, f"scenario threw: {results['__error']}"
    return results


def _scenario_context(report=None) -> tuple[str, list[str]]:
    """Return (embedded script, chip onclicks) for the sample cockpit page.

    Pass an existing ``report`` so the assertions compare against the very same
    CBOM that was embedded in the page (the serial number is generated per
    report build).
    """
    if report is None:
        report = _build_report()
    html = generate_cockpit_html(report)
    return _extract_script(html), _extract_chip_onclicks(html)


# --- renderCompliance -------------------------------------------------------

_COMPLIANCE_SCENARIO = r"""
function __scenario() {
  renderCompliance();
  __results.nFlags = complianceFlags.length;
  __results.items = document.getElementById("complianceList")
    .__children.map(function (d) { return d.innerHTML; });
  __results.className = document.getElementById("complianceList")
    .__children.map(function (d) { return d.className; });
  __results.rawFlags = complianceFlags.slice();
}
"""

def test_cockpit_js_render_compliance_lists_every_flag(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _COMPLIANCE_SCENARIO, tmp_path)
    report = _build_report()

    assert out["nFlags"] == len(report.compliance_flags)
    assert out["nFlags"] > 0, "sample report must carry compliance flags"
    assert out["rawFlags"] == list(report.compliance_flags)
    assert len(out["items"]) == len(report.compliance_flags)
    for flag, item_html, cls in zip(report.compliance_flags, out["items"], out["className"]):
        assert flag in item_html, f"flag {flag!r} missing from rendered item"
        assert cls == "compliance-item"
        assert "Mevzuat gereği klasik anahtarlar" in item_html


_COMPLIANCE_EMPTY_SCENARIO = r"""
function __scenario() {
  complianceFlags.length = 0;
  renderCompliance();
  __results.emptyChildren = document.getElementById("complianceList").__children.length;
  __results.okBanner = document.getElementById("complianceList").innerHTML;
}
"""

def test_cockpit_js_render_compliance_empty_shows_all_clear_banner(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _COMPLIANCE_EMPTY_SCENARIO, tmp_path)

    assert out["emptyChildren"] == 0, "empty branch must set innerHTML, not append nodes"
    assert "✅ Kritik yasal uyumsuzluk tespit edilmedi" in out["okBanner"]
    assert "compliance-item ok" in out["okBanner"]


# --- openDrawer / closeDrawer -----------------------------------------------

_DRAWER_SCENARIO = r"""
function __scenario() {
  var c = components.find(function (x) { return x.shor; });
  openDrawer(c);
  var drawer = document.getElementById("drawer");
  var backdrop = document.getElementById("drawerBackdrop");
  __results.drawerOpen = drawer.classList.contains("open");
  __results.backdropOpen = backdrop.classList.contains("open");
  __results.content = document.getElementById("drawerContent").innerHTML;
  __results.name = c.name;
  __results.algo = c.algo;
  __results.keySize = c.keySize;
  __results.type = c.type;
  __results.nistLevel = c.nistLevel;
  __results.replacement = c.replacement;
  __results.oid = c.oid;
  __results.ref = c.ref;
  closeDrawer();
  __results.drawerClosed = !drawer.classList.contains("open");
  __results.backdropClosed = !backdrop.classList.contains("open");
}
"""

def test_cockpit_js_open_drawer_renders_asset_fields_and_opens_state(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _DRAWER_SCENARIO, tmp_path)

    assert out["drawerOpen"] and out["backdropOpen"]
    content = out["content"]
    assert out["name"] in content
    assert f"{out['algo']} ({out['keySize']} bit)" in content
    assert out["type"] in content
    assert f"Seviye {out['nistLevel']}" in content
    # Shor-vulnerable asset selected -> affirmative HNDL verdict
    assert "EVET — Polinomik Zamanlı Kırılabilir" in content
    assert out["replacement"] in content
    assert out["oid"] in content
    assert out["ref"] in content
    assert f"copyGuidance('{out['replacement']}')" in content
    # closeDrawer must clear the open state on both elements
    assert out["drawerClosed"] and out["backdropClosed"]


_DRAWER_SAFE_SCENARIO = r"""
function __scenario() {
  var c = components.find(function (x) { return !x.shor; });
  openDrawer(c);
  __results.content = document.getElementById("drawerContent").innerHTML;
  __results.nistLevel = c.nistLevel;
}
"""

def test_cockpit_js_open_drawer_quantum_safe_asset_shows_negative_verdict(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _DRAWER_SAFE_SCENARIO, tmp_path)

    assert "HAYIR — Kuantum Dayanıklı" in out["content"]
    assert "EVET —" not in out["content"]
    if out["nistLevel"] == 0:
        assert "(Kuantum Öncesi - Zayıf)" in out["content"]
    else:
        assert "(PQC Standart)" in out["content"]


# --- downloadCsv ------------------------------------------------------------

_CSV_SCENARIO = r"""
function __scenario() {
  downloadCsv();
  var blob = __blobs[__blobs.length - 1];
  __results.blobType = blob.opts.type;
  __results.csv = blob.parts.join("");
  __results.filename = __lastAnchor.download;
  __results.anchorClicked = __lastAnchor.__clicked;
  __results.nComponents = components.length;
  var expected = "Name,Type,Algorithm,KeySize,NistLevel,ShorVulnerable,RecommendedReplacement,OID\n";
  components.forEach(function (c) {
    expected += '"' + c.name + '","' + c.type + '","' + c.algo + '",'
      + c.keySize + ',' + c.nistLevel + ',' + c.shor + ',"'
      + c.replacement + '","' + c.oid + '"\n';
  });
  __results.expectedCsv = expected;
}
"""

def test_cockpit_js_download_csv_serializes_full_inventory(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _CSV_SCENARIO, tmp_path)

    assert out["blobType"] == "text/csv"
    assert out["anchorClicked"] is True, "download anchor must be clicked"
    assert out["filename"] == f"pqc-inventory-{_TARGET}.csv"
    assert out["nComponents"] == len(_SAMPLE_ASSETS)

    csv = out["csv"]
    assert csv == out["expectedCsv"], "CSV must match the documented column layout"
    lines = csv.split("\n")
    assert lines[0] == ("Name,Type,Algorithm,KeySize,NistLevel,ShorVulnerable,"
                        "RecommendedReplacement,OID")
    # header + one row per component + trailing empty string after final \n
    assert len(lines) == len(_SAMPLE_ASSETS) + 2
    for asset in _SAMPLE_ASSETS:
        row = next(ln for ln in lines if f'"{asset["name"]}"' in ln)
        assert f'"{asset["algorithm"]}"' in row
        assert asset["type"] in row


# --- downloadVc -------------------------------------------------------------

_VC_SCENARIO = r"""
function __scenario() {
  downloadVc();
  var blob = __blobs[__blobs.length - 1];
  __results.blobType = blob.opts.type;
  __results.vcJson = blob.parts.join("");
  __results.filename = __lastAnchor.download;
}
"""

_ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def test_cockpit_js_download_vc_emits_w3c_attestation(tmp_path):
    report = _build_report()
    script, chips = _scenario_context(report)
    out = _run_scenario(script, chips, _VC_SCENARIO, tmp_path)

    assert out["blobType"] == "application/json"
    assert out["filename"] == f"pqc-attestation-vc-{_TARGET}.csv".replace(".csv", ".json")

    vc = json.loads(out["vcJson"])
    assert vc["@context"] == [
        "https://www.w3.org/ns/credentials/v2",
        "https://schema.pqhaven.io/pqc-attestation/v1",
    ]
    assert vc["type"] == ["VerifiableCredential", "PqcPostureAttestation"]
    assert vc["issuer"] == "did:pqhaven:auditor:0x1b24"
    assert _ISO8601_RE.match(vc["validFrom"]), "validFrom must be an ISO-8601 UTC stamp"

    serial = report.cbom.model_dump(by_alias=True)["serialNumber"]
    assert vc["id"] == "urn:uuid:" + serial.split(":")[-1]

    subject = vc["credentialSubject"]
    assert subject["targetEndpoint"] == report.target
    assert subject["cbomMerkleRoot"] == "0x" + report.merkle_root
    assert subject["hndlVulnerabilities"] == report.hndl_vulnerability_count
    assert subject["totalCryptoAssets"] == len(_SAMPLE_ASSETS)
    assert subject["complianceFlags"] == list(report.compliance_flags)
    assert subject["onChainRegistryContract"] == "0x446B847e096B408B48B4bEeeFd0F4D3C23B99511"


# --- toggleGraphPhysics -----------------------------------------------------

_PHYSICS_SCENARIO = r"""
function __scenario() {
  __results.initial = physicsActive;
  __results.labelInitial = document.getElementById("btnTogglePhysics").innerText;
  toggleGraphPhysics();
  __results.afterFirst = physicsActive;
  __results.labelAfterFirst = document.getElementById("btnTogglePhysics").innerText;
  toggleGraphPhysics();
  __results.afterSecond = physicsActive;
  __results.labelAfterSecond = document.getElementById("btnTogglePhysics").innerText;
}
"""

def test_cockpit_js_toggle_graph_physics_flips_state_and_label(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _PHYSICS_SCENARIO, tmp_path)

    # physics starts active; each toggle flips the flag and rewrites the label
    assert out["initial"] is True
    assert out["afterFirst"] is False
    assert out["labelAfterFirst"] == "▶️ Başlat", "paused physics offers 'Start'"
    assert out["afterSecond"] is True
    assert out["labelAfterSecond"] == "⏸ Duraklat", "resumed physics offers 'Pause'"


# --- focusCriticalNodes -----------------------------------------------------

_FOCUS_CRITICAL_SCENARIO = r"""
function __scenario() {
  focusCriticalNodes();
  __results.category = currentCategory;
  __results.nShor = components.filter(function (c) { return c.shor; }).length;
  __results.rows = document.querySelector("#assetTable tbody").__children
    .map(function (tr) { return tr.innerHTML; });
  __results.activeChips = __chips
    .filter(function (c) { return c.classList.contains("active"); })
    .map(function (c) { return c.getAttribute("onclick"); });
}
"""

def test_cockpit_js_focus_critical_nodes_applies_shor_filter(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _FOCUS_CRITICAL_SCENARIO, tmp_path)

    assert out["category"] == "shor"
    assert "setFilterCategory('shor', this)" in chips
    assert out["activeChips"] == ["setFilterCategory('shor', this)"]
    assert len(out["rows"]) == out["nShor"]
    assert out["nShor"] > 0
    for row in out["rows"]:
        assert "badge-critical" in row, "focused rows must all be Shor-critical"
