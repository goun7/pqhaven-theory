"""Data-logic tests for the PQHaven cockpit's in-page JavaScript.

The Executive Cockpit is a single self-contained HTML page whose interactive
logic (table sorting, asset filtering, MOSCA verdicts, live Monte Carlo,
clipboard export, CBOM download) lives in an embedded ``<script>`` block.
These tests extract that script from :func:`pqhaven.cockpit.generate_cockpit_html`
and execute it inside Node against a minimal DOM/clipboard mock, so the *real*
data-processing functions are exercised without a browser or heavy canvas
rendering.
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

_MC_STATS_RE = re.compile(
    r"HNDL Zafiyet Riski: %(?P<prob>[\d.]+) \(95% CI: \[%(?P<lo>-?[\d.]+), %(?P<hi>-?[\d.]+)\]\)"
)


def _run_scenario(script: str, chips: list[str], scenario_body: str, tmp_path) -> dict:
    """Run the cockpit script + a scenario in Node and return the collected results."""
    harness = (
        _HARNESS_PRE.replace("__CHIPS_JSON__", json.dumps(chips))
        + "\n" + script + "\n"
        + _HARNESS_POST.replace("__SCENARIO_BODY__", scenario_body)
    )
    path = tmp_path / "cockpit_harness.js"
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


def _scenario_context() -> tuple[str, list[str]]:
    """Return (embedded script, chip onclicks) for the sample cockpit page."""
    report = _build_report()
    html = generate_cockpit_html(report)
    return _extract_script(html), _extract_chip_onclicks(html)


# --- sortTable --------------------------------------------------------------

_SORT_SCENARIO = r"""
function __scenario() {
  __results.before = components.map(function (c) { return c.name; });
  sortTable(0);                       // "name" ascending
  __results.nameAsc = components.map(function (c) { return c.name; });
  sortTable(0);                       // "name" descending
  __results.nameDesc = components.map(function (c) { return c.name; });
  sortTable(3);                       // "keySize" ascending
  __results.keySizeAsc = components.map(function (c) { return c.keySize; });
  sortTable(3);                       // "keySize" descending
  __results.keySizeDesc = components.map(function (c) { return c.keySize; });
}
"""

def test_cockpit_js_sort_table_sorts_strings_and_numbers(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _SORT_SCENARIO, tmp_path)

    before = out["before"]
    assert len(before) == len(_SAMPLE_ASSETS)
    assert before == [a["name"] for a in _SAMPLE_ASSETS]
    assert out["nameAsc"] == sorted(before), "first sort must be ascending"
    assert out["nameDesc"] == sorted(before, reverse=True), "second sort must flip order"
    # numeric column must compare numerically, not lexically
    assert out["keySizeAsc"] == sorted(out["keySizeAsc"])
    assert out["keySizeAsc"] == [128, 256, 768, 2048, 3072]
    assert out["keySizeDesc"] == out["keySizeAsc"][::-1]


# --- filterAssets -----------------------------------------------------------

_FILTER_QUERY_SCENARIO = r"""
function __rows() {
  return document.querySelector("#assetTable tbody").__children
    .map(function (tr) { return tr.innerHTML; });
}
function __scenario() {
  var fi = document.getElementById("filterInput");
  fi.value = "rsa";
  filterAssets();
  __results.rsaRows = __rows();
  fi.value = "zzzz-not-found";
  filterAssets();
  __results.emptyRows = __rows();
  fi.value = "signing-service";
  filterAssets();
  __results.nameRows = __rows();
  fi.value = "ml-dsa-65";
  filterAssets();
  __results.replacementRows = __rows();
}
"""

def test_cockpit_js_filter_assets_matches_name_algo_type_and_replacement(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _FILTER_QUERY_SCENARIO, tmp_path)

    assert len(out["rsaRows"]) == 2, "RSA-2048 cert + RSA-3072 protocol match 'rsa'"
    for row in out["rsaRows"]:
        assert "rsa" in row.lower()
    assert out["emptyRows"] == [], "non-matching query must render no rows"
    assert len(out["nameRows"]) == 1, "'signing-service' matches only that asset name"
    assert "signing-service" in out["nameRows"][0]
    # 'ml-dsa-65' only appears in the recommended replacement of the RSA assets
    assert len(out["replacementRows"]) == 2
    for row in out["replacementRows"]:
        assert "ml-dsa-65" in row.lower()


# --- setFilterCategory ------------------------------------------------------

_FILTER_CATEGORY_SCENARIO = r"""
function __rows() {
  return document.querySelector("#assetTable tbody").__children
    .map(function (tr) { return tr.innerHTML; });
}
function __scenario() {
  setFilterCategory("shor", null);
  __results.categoryAfterShor = currentCategory;
  __results.shorRows = __rows();
  __results.activeChips = __chips
    .filter(function (c) { return c.classList.contains("active"); })
    .map(function (c) { return c.getAttribute("onclick"); });
  setFilterCategory("certificate", null);
  __results.certRows = __rows();
  setFilterCategory("key", null);
  __results.keyRows = __rows();
  setFilterCategory("ready", null);
  __results.readyRows = __rows();
}
"""

def test_cockpit_js_set_filter_category_filters_and_activates_chip(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _FILTER_CATEGORY_SCENARIO, tmp_path)

    assert "setFilterCategory('shor', this)" in chips
    assert out["categoryAfterShor"] == "shor"
    # RSA-2048, RSA-3072 and ECDH-X25519 are Shor-vulnerable in the sample
    assert len(out["shorRows"]) == 3
    for row in out["shorRows"]:
        assert "badge-critical" in row
    # exactly the matching chip gets the .active class via the null-element path
    assert out["activeChips"] == ["setFilterCategory('shor', this)"]
    assert len(out["certRows"]) == 1 and ">certificate<" in out["certRows"][0]
    assert len(out["keyRows"]) == 1 and ">key<" in out["keyRows"][0]
    assert len(out["readyRows"]) == 2
    for row in out["readyRows"]:
        assert "badge-ready" in row


# --- updateMosca ------------------------------------------------------------

_MOSCA_SCENARIO = r"""
function __setSliders(x, y, z) {
  document.getElementById("sliderX").value = String(x);
  document.getElementById("sliderY").value = String(y);
  document.getElementById("sliderZ").value = String(z);
}
function __scenario() {
  __setSliders(5, 5, 3);
  updateMosca();
  var v = document.getElementById("simVerdict");
  __results.dangerText = v.innerText;
  __results.dangerBg = v.style.background;
  __results.dangerColor = v.style.color;
  __results.valX = document.getElementById("valX").innerText;

  __setSliders(1, 1, 10);
  updateMosca();
  __results.safeText = v.innerText;
  __results.safeBg = v.style.background;

  __setSliders(2, 2, 4);  // X + Y == Z -> boundary is not dangerous
  updateMosca();
  __results.boundaryText = v.innerText;
}
"""

def test_cockpit_js_update_mosca_flags_x_plus_y_greater_than_z(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _MOSCA_SCENARIO, tmp_path)

    assert out["valX"] == "5 Yıl"
    assert "TEHLİKE" in out["dangerText"]
    assert "10.0 Yıl" in out["dangerText"]
    assert "3.0 Yıl" in out["dangerText"]
    assert "244,63,94" in out["dangerBg"]

    assert "GÜVENLİ" in out["safeText"]
    assert "2.0 Yıl" in out["safeText"]
    assert "10.0 Yıl" in out["safeText"]
    assert "16,185,129" in out["safeBg"]

    assert "GÜVENLİ" in out["boundaryText"], "X+Y == Z must read as safe"


# --- runLiveMonteCarlo ------------------------------------------------------

_MONTE_CARLO_SCENARIO = r"""
function __scenario() {
  __resetSeed(987654);
  runLiveMonteCarlo();
  __results.stats1 = document.getElementById("mcStatsText").innerText;
  __resetSeed(987654);
  runLiveMonteCarlo();
  __results.stats2 = document.getElementById("mcStatsText").innerText;
  __resetSeed(11111);
  runLiveMonteCarlo();
  __results.stats3 = document.getElementById("mcStatsText").innerText;
  __results.histFillRects = document.getElementById("histogramCanvas").getContext()._fillRects;
}
"""

def test_cockpit_js_run_live_monte_carlo_is_valid_and_deterministic(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _MONTE_CARLO_SCENARIO, tmp_path)

    assert out["stats1"] == out["stats2"], "same RNG seed must reproduce the result"

    for key in ("stats1", "stats3"):
        m = _MC_STATS_RE.search(out[key])
        assert m is not None, f"unexpected stats format: {out[key]!r}"
        prob = float(m.group("prob"))
        lo = float(m.group("lo"))
        hi = float(m.group("hi"))
        assert 0.0 <= prob <= 100.0
        assert lo <= prob <= hi, "point estimate must lie inside its 95% CI"
        assert 0.0 <= (hi - lo) < 3.0, f"CI too wide for N=10000: {hi - lo}"

    assert out["histFillRects"] > 0
    assert out["histFillRects"] % 24 == 0, "histogram must draw exactly 24 bins per run"


# --- copyGuidance -----------------------------------------------------------

_COPY_GUIDANCE_SCENARIO = r"""
function __scenario() {
  copyGuidance("ML-KEM-768");
  copyGuidance("SLH-DSA-SHA2-256s");
  __results.clipboard = __clipboard.slice();
}
"""

def test_cockpit_js_copy_guidance_writes_migration_target_to_clipboard(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _COPY_GUIDANCE_SCENARIO, tmp_path)

    assert out["clipboard"] == [
        "// PQHaven Migration Target: ML-KEM-768",
        "// PQHaven Migration Target: SLH-DSA-SHA2-256s",
    ]


# --- copyExecutiveSummary ---------------------------------------------------

_COPY_SUMMARY_SCENARIO = r"""
function __scenario() {
  copyExecutiveSummary();
  __results.summary = __clipboard[0];
  __results.targetName = targetName;
  __results.pqriScore = pqriScore;
  __results.nComponents = components.length;
  __results.nShor = components.filter(function (c) { return c.shor; }).length;
  __results.merkleRoot = merkleRoot;
}
"""

def test_cockpit_js_copy_executive_summary_content_matches_report(tmp_path):
    script, chips = _scenario_context()
    out = _run_scenario(script, chips, _COPY_SUMMARY_SCENARIO, tmp_path)

    summary = out["summary"]
    assert out["targetName"] == _TARGET
    assert summary.startswith("# PQHaven Kriptografik Denetim Özeti")
    assert f"**Hedef:** {_TARGET}" in summary
    assert f"**PQRI Risk Skoru:** {out['pqriScore']} / 100" in summary
    assert f"**Toplam Varlık Sayısı:** {out['nComponents']}" in summary
    assert f"**Shor Zafiyetli Varlık:** {out['nShor']}" in summary
    assert summary.endswith("*PQHaven Autonomous Crypto-Agility Engine tarafından oluşturuldu.*")
    if out["merkleRoot"]:
        assert f"0x{out['merkleRoot']}" in summary


# --- downloadCbom -----------------------------------------------------------

_DOWNLOAD_CBOM_SCENARIO = r"""
function __scenario() {
  downloadCbom();
  var blob = __blobs[__blobs.length - 1];
  __results.blobType = blob.opts.type;
  __results.blobJson = blob.parts.join("");
  __results.filename = __lastAnchor.download;
}
"""

def test_cockpit_js_download_cbom_exports_serialized_cbom(tmp_path):
    report = _build_report()
    html = generate_cockpit_html(report)
    script, chips = _extract_script(html), _extract_chip_onclicks(html)
    out = _run_scenario(script, chips, _DOWNLOAD_CBOM_SCENARIO, tmp_path)

    assert out["blobType"] == "application/json"
    exported = json.loads(out["blobJson"])
    expected = report.cbom.model_dump(by_alias=True)
    assert exported == expected, "downloaded blob must equal the CBOM payload"
    serial = exported["serialNumber"]
    assert out["filename"] == f"cbom-{serial.replace(':', '-')}.json"
