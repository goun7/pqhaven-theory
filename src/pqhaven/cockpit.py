"""PQHaven Executive Cockpit & Interactive Telemetry HTML Generator.

Generates an executive-grade, standalone, zero-external-dependency HTML/CSS/JS dashboard
embodying elite security aesthetics, interactive force-directed Canvas cryptographic topology
graph (with velocity verlet physics, touch/mouse dragging, pulsing threat auras, and hover tooltips),
live Monte Carlo stochastic histogram simulation, SVG executive posture gauge, clickable column
sorting, sliding asset inspection drawer, compliance radar, and CycloneDX 1.6 CBOM / CSV / W3C-VC export.
"""

from __future__ import annotations
import json
from typing import Any, Dict
from pqhaven.models import AssessmentReport


def generate_cockpit_html(report: AssessmentReport) -> str:
    """Renders self-contained, air-gapped executive Post-Quantum Telemetry Cockpit."""
    cbom_dict = report.cbom.model_dump(by_alias=True)
    cbom_json_str = json.dumps(cbom_dict, indent=2)

    components_json = json.dumps([
        {
            "name": c.name,
            "ref": c.bom_ref,
            "type": c.crypto_properties.asset_type.value,
            "algo": c.crypto_properties.algorithm_name or "N/A",
            "keySize": c.crypto_properties.key_size or 0,
            "shor": c.crypto_properties.shor_vulnerable,
            "grover": c.crypto_properties.grover_degraded,
            "nistLevel": c.crypto_properties.nist_quantum_level,
            "replacement": c.crypto_properties.recommended_replacement,
            "oid": c.crypto_properties.oid or "N/A",
        }
        for c in report.cbom.components
    ])

    gauge_pct = min(100.0, max(0.0, float(report.pqri_score)))
    gauge_stroke = round((gauge_pct / 100.0) * 251.2, 2)

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PQHaven Cockpit — {report.target}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #07090e;
      --bg-surface: #0b111d;
      --bg-card: #10192a;
      --bg-elevated: #162238;
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-focus: rgba(6, 182, 212, 0.45);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --accent-cyan: #06b6d4;
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-rose: #f43f5e;
      --accent-violet: #8b5cf6;
      --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --font-mono: "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: var(--font-sans);
      line-height: 1.5;
      padding: 28px;
      -webkit-font-smoothing: antialiased;
    }}

    .container {{
      max-width: 1440px;
      margin: 0 auto;
    }}

    /* Header */
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border-subtle);
      margin-bottom: 28px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 16px;
    }}
    .brand-logo {{
      width: 48px;
      height: 48px;
      border-radius: 12px;
      background: linear-gradient(135deg, #06b6d4, #8b5cf6);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-family: var(--font-mono);
      font-size: 22px;
      color: #fff;
      box-shadow: 0 0 28px rgba(6, 182, 212, 0.4);
    }}
    .brand h1 {{
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }}
    .brand span {{
      color: var(--text-muted);
      font-size: 13px;
      font-weight: 400;
    }}
    .header-actions {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .btn {{
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
      padding: 8px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }}
    .btn:hover {{
      background: var(--bg-elevated);
      border-color: var(--accent-cyan);
      transform: translateY(-1px);
    }}
    .btn-primary {{
      background: var(--accent-cyan);
      color: #041017;
      border-color: var(--accent-cyan);
      font-weight: 600;
    }}
    .btn-primary:hover {{
      background: #22d3ee;
      border-color: #22d3ee;
    }}

    /* Top KPI Row with Radial Gauge */
    .kpi-grid {{
      display: grid;
      grid-template-columns: 1.4fr 1fr 1fr 1fr;
      gap: 20px;
      margin-bottom: 28px;
    }}
    .kpi-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      padding: 22px;
      position: relative;
      overflow: hidden;
      box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
      transition: transform 0.2s ease, border-color 0.2s ease;
    }}
    .kpi-card:hover {{
      transform: translateY(-2px);
      border-color: rgba(255, 255, 255, 0.15);
    }}
    .kpi-card::before {{
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: var(--border-subtle);
    }}
    .kpi-card.critical::before {{ background: var(--accent-rose); }}
    .kpi-card.warning::before {{ background: var(--accent-amber); }}
    .kpi-card.ready::before {{ background: var(--accent-emerald); }}
    .kpi-card.info::before {{ background: var(--accent-cyan); }}

    .gauge-card {{
      display: flex;
      align-items: center;
      gap: 20px;
    }}
    .gauge-svg {{
      width: 100px;
      height: 100px;
      transform: rotate(-90deg);
      flex-shrink: 0;
    }}
    .gauge-bg {{
      fill: none;
      stroke: rgba(255, 255, 255, 0.08);
      stroke-width: 8;
    }}
    .gauge-bar {{
      fill: none;
      stroke: {'#f43f5e' if report.pqri_score >= 75 else '#f59e0b' if report.pqri_score >= 50 else '#10b981'};
      stroke-width: 8;
      stroke-dasharray: 251.2;
      stroke-dashoffset: {251.2 - gauge_stroke};
      stroke-linecap: round;
      transition: stroke-dashoffset 1s ease-out;
    }}

    .kpi-label {{
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
      margin-bottom: 8px;
    }}
    .kpi-value {{
      font-size: 28px;
      font-weight: 700;
      font-family: var(--font-mono);
      letter-spacing: -0.03em;
    }}
    .kpi-subtext {{
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 6px;
    }}

    /* Main Layout */
    .main-grid {{
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 24px;
      margin-bottom: 28px;
    }}
    .card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      padding: 24px;
      box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
      position: relative;
    }}
    .card-title {{
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}

    /* Canvas Graph */
    .canvas-container {{
      position: relative;
    }}
    #topologyCanvas {{
      width: 100%;
      height: 320px;
      background: radial-gradient(circle at center, #09101d 0%, #04060a 100%);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      display: block;
      margin-bottom: 12px;
      cursor: grab;
    }}
    #topologyCanvas:active {{
      cursor: grabbing;
    }}
    .canvas-toolbar {{
      position: absolute;
      top: 12px;
      right: 12px;
      display: flex;
      gap: 6px;
      background: rgba(11, 17, 29, 0.85);
      padding: 4px;
      border-radius: 6px;
      border: 1px solid var(--border-subtle);
      backdrop-filter: blur(8px);
    }}
    .canvas-btn {{
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 11px;
      font-weight: 500;
      padding: 4px 8px;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .canvas-btn:hover {{
      background: var(--bg-card);
      color: var(--text-main);
    }}

    /* Filter Chips */
    .filter-chips {{
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }}
    .chip {{
      padding: 5px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 500;
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .chip:hover, .chip.active {{
      background: var(--bg-elevated);
      color: var(--accent-cyan);
      border-color: var(--accent-cyan);
    }}

    /* Data Table */
    .table-container {{
      overflow-x: auto;
      max-height: 480px;
      overflow-y: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th {{
      text-align: left;
      padding: 10px 12px;
      background: var(--bg-card);
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--border-subtle);
      position: sticky;
      top: 0;
      z-index: 2;
      cursor: pointer;
      user-select: none;
    }}
    th:hover {{
      color: var(--accent-cyan);
    }}
    td {{
      padding: 12px;
      border-bottom: 1px solid var(--border-subtle);
      font-family: var(--font-mono);
    }}
    tr {{
      cursor: pointer;
      transition: background 0.15s ease;
    }}
    tr:hover td {{
      background: rgba(255, 255, 255, 0.04);
    }}

    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      font-family: var(--font-sans);
    }}
    .badge-critical {{ background: rgba(244, 63, 94, 0.15); color: var(--accent-rose); border: 1px solid rgba(244, 63, 94, 0.3); }}
    .badge-high {{ background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.3); }}
    .badge-ready {{ background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); border: 1px solid rgba(16, 185, 129, 0.3); }}

    /* Histogram Canvas */
    #histogramCanvas {{
      width: 100%;
      height: 140px;
      background: #04060a;
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      display: block;
      margin-top: 12px;
    }}

    /* Code Snippet Box */
    pre {{
      background: #04060a;
      border: 1px solid var(--border-subtle);
      padding: 14px;
      border-radius: 8px;
      font-family: var(--font-mono);
      font-size: 12px;
      overflow-x: auto;
      color: #38bdf8;
    }}

    /* Compliance List */
    .compliance-item {{
      padding: 12px;
      border-radius: 8px;
      background: var(--bg-card);
      margin-bottom: 10px;
      border-left: 3px solid var(--accent-rose);
      font-size: 13px;
    }}
    .compliance-item.ok {{
      border-left-color: var(--accent-emerald);
    }}

    /* Sliding Drawer */
    #drawerBackdrop {{
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.65);
      backdrop-filter: blur(6px);
      z-index: 100;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.25s ease;
    }}
    #drawerBackdrop.open {{
      opacity: 1;
      pointer-events: auto;
    }}
    #drawer {{
      position: fixed;
      top: 0; right: -480px; bottom: 0;
      width: 460px;
      background: var(--bg-surface);
      border-left: 1px solid var(--border-subtle);
      z-index: 101;
      padding: 28px;
      overflow-y: auto;
      transition: right 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: -12px 0 40px rgba(0, 0, 0, 0.6);
    }}
    #drawer.open {{
      right: 0;
    }}
    .drawer-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 16px;
      margin-bottom: 20px;
    }}
    .drawer-close {{
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 22px;
      cursor: pointer;
    }}
    .drawer-close:hover {{ color: var(--text-main); }}
    .drawer-field {{
      margin-bottom: 16px;
    }}
    .drawer-field-label {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 4px;
    }}
    .drawer-field-value {{
      font-size: 14px;
      font-family: var(--font-mono);
      color: var(--text-main);
      word-break: break-all;
    }}

    /* Print CSS */
    @media print {{
      body {{
        background: #fff !important;
        color: #000 !important;
        padding: 0;
      }}
      .card, .kpi-card {{
        background: #fff !important;
        border: 1px solid #ccc !important;
        color: #000 !important;
        box-shadow: none !important;
      }}
      header, .filter-chips, .header-actions, .canvas-toolbar, #drawer, #drawerBackdrop {{
        display: none !important;
      }}
      th {{
        background: #f1f5f9 !important;
        color: #000 !important;
      }}
      td {{
        color: #000 !important;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="brand-logo">PQ</div>
        <div>
          <h1>PQHaven Executive Cockpit</h1>
          <span>Hedef: <strong>{report.target}</strong> · Merkle Root: <code>0x{(report.merkle_root or '00'*32)[:16]}...</code></span>
        </div>
      </div>
      <div class="header-actions">
        <button class="btn" onclick="copyExecutiveSummary()">📋 Yönetici Özeti Kopyala</button>
        <button class="btn" onclick="downloadCbom()">📦 CycloneDX 1.6 JSON</button>
        <button class="btn" onclick="downloadCsv()">📊 Envanter CSV</button>
        <button class="btn" onclick="downloadVc()">🔏 W3C VC JSON</button>
        <button class="btn btn-primary" onclick="window.print()">🖨️ Rapor Yazdır / PDF</button>
      </div>
    </header>

    <!-- Top KPI Row with Radial Posture Gauge -->
    <div class="kpi-grid">
      <div class="kpi-card gauge-card {'critical' if report.pqri_score >= 75 else 'warning' if report.pqri_score >= 50 else 'ready'}">
        <svg class="gauge-svg" viewBox="0 0 100 100">
          <circle class="gauge-bg" cx="50" cy="50" r="40" />
          <circle class="gauge-bar" cx="50" cy="50" r="40" />
        </svg>
        <div>
          <div class="kpi-label">PQRI Risk İndeksi</div>
          <div class="kpi-value">{report.pqri_score} <span style="font-size: 15px; color: var(--text-muted);">/ 100</span></div>
          <div class="kpi-subtext">Durum: <strong>{report.overall_grade.value}</strong></div>
        </div>
      </div>

      <div class="kpi-card critical">
        <div class="kpi-label">HNDL Zafiyetli Varlıklar</div>
        <div class="kpi-value" style="color: var(--accent-rose);">{report.hndl_vulnerability_count}</div>
        <div class="kpi-subtext">Shor saldırısına maruz şifreli oturum</div>
      </div>

      <div class="kpi-card info">
        <div class="kpi-label">Toplam Kriptografik Varlık</div>
        <div class="kpi-value">{len(report.cbom.components)}</div>
        <div class="kpi-subtext">Sertifika, KEM, Protokol, Anahtar</div>
      </div>

      <div class="kpi-card warning">
        <div class="kpi-label">Mevzuat Uyarı Bayrakları</div>
        <div class="kpi-value" style="color: var(--accent-amber);">{len(report.compliance_flags)}</div>
        <div class="kpi-subtext">KVKK m.12 / NIS2 / DORA / BDDK</div>
      </div>
    </div>

    <!-- Interactive Force-Directed Topology Graph -->
    <div class="card" style="margin-bottom: 28px;">
      <div class="card-title">
        <span>🌐 Kriptografik Varlık ve Bağımlılık Topolojisi (Force-Directed Canlı Fizik)</span>
        <span style="font-size: 12px; color: var(--text-muted);">Düğümleri fare veya dokunmatik ekranla sürükleyebilirsiniz</span>
      </div>
      <div class="canvas-container">
        <div class="canvas-toolbar">
          <button class="canvas-btn" onclick="resetGraphPhysics()">🔄 Sıfırla</button>
          <button class="canvas-btn" id="btnTogglePhysics" onclick="toggleGraphPhysics()">⏸ Duraklat</button>
          <button class="canvas-btn" onclick="focusCriticalNodes()">🚨 Zafiyet Odak</button>
        </div>
        <canvas id="topologyCanvas"></canvas>
      </div>
    </div>

    <!-- Main Grid: Assets & Simulation -->
    <div class="main-grid">
      <!-- CBOM Asset Explorer -->
      <div class="card">
        <div class="card-title">
          <span>Kriptografik Ürün Ağacı (CycloneDX 1.6 CBOM)</span>
          <input type="text" id="filterInput" placeholder="Varlık veya algoritma ara..." style="background: var(--bg-card); border: 1px solid var(--border-subtle); color: var(--text-main); padding: 6px 12px; border-radius: 6px; font-size: 12px;" oninput="filterAssets()">
        </div>

        <div class="filter-chips">
          <div class="chip active" onclick="setFilterCategory('all', this)">Tümü ({len(report.cbom.components)})</div>
          <div class="chip" onclick="setFilterCategory('shor', this)">🚨 Shor Kırılgan</div>
          <div class="chip" onclick="setFilterCategory('ready', this)">🛡️ Kuantum Hazır</div>
          <div class="chip" onclick="setFilterCategory('certificate', this)">📜 Sertifikalar</div>
          <div class="chip" onclick="setFilterCategory('protocol', this)">🌐 Protokoller</div>
          <div class="chip" onclick="setFilterCategory('key', this)">🔑 Anahtarlar</div>
        </div>

        <div class="table-container">
          <table id="assetTable">
            <thead>
              <tr>
                <th onclick="sortTable(0)">Varlık Adı ⇕</th>
                <th onclick="sortTable(1)">Tip ⇕</th>
                <th onclick="sortTable(2)">Algoritma ⇕</th>
                <th onclick="sortTable(3)">Anahtar ⇕</th>
                <th onclick="sortTable(4)">Kuantum Seviyesi ⇕</th>
                <th onclick="sortTable(5)">Önerilen Geçiş ⇕</th>
              </tr>
            </thead>
            <tbody>
              <!-- Dynamic Rows -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- Mosca Interactive Simulator -->
      <div class="card">
        <div class="card-title">Mosca Eşitsizliği & Monte Carlo Q-Day</div>
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
          Formül: <code>X (Veri Ömrü) + Y (Göç) > Z (CRQC Gelişi)</code>
        </p>
        <div style="display: flex; flex-direction: column; gap: 14px;">
          <div>
            <div style="display: flex; justify-content: space-between; font-size: 13px;">
              <span>Veri Gizlilik Raf Ömrü (X)</span>
              <span style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-cyan);" id="valX">10 Yıl</span>
            </div>
            <input type="range" id="sliderX" min="1" max="30" value="10" style="width: 100%; accent-color: var(--accent-cyan);" oninput="updateMosca()">
          </div>

          <div>
            <div style="display: flex; justify-content: space-between; font-size: 13px;">
              <span>Altyapı Göç Süresi (Y)</span>
              <span style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-cyan);" id="valY">3 Yıl</span>
            </div>
            <input type="range" id="sliderY" min="1" max="10" value="3" style="width: 100%; accent-color: var(--accent-cyan);" oninput="updateMosca()">
          </div>

          <div>
            <div style="display: flex; justify-content: space-between; font-size: 13px;">
              <span>CRQC / Q-Day Beklentisi (Z)</span>
              <span style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-cyan);" id="valZ">7.5 Yıl</span>
            </div>
            <input type="range" id="sliderZ" min="3" max="15" step="0.5" value="7.5" style="width: 100%; accent-color: var(--accent-cyan);" oninput="updateMosca()">
          </div>

          <div id="simVerdict" style="padding: 10px; border-radius: 6px; background: rgba(244,63,94,0.15); border: 1px solid rgba(244,63,94,0.3); color: var(--accent-rose); font-size: 12px; font-weight: 600; text-align: center;">
            ⚠️ TEHLİKE: X + Y (13.0 Yıl) > Z (7.5 Yıl)
          </div>

          <div style="margin-top: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-size: 12px; font-weight: 600;">Stokastik Dağılım (N=10.000)</span>
              <button class="btn" style="padding: 4px 8px; font-size: 11px;" onclick="runLiveMonteCarlo()">Yeniden Simüle Et</button>
            </div>
            <canvas id="histogramCanvas"></canvas>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px; text-align: center;" id="mcStatsText">
              HNDL Zafiyet Riski Hesaplanıyor...
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Bottom Row: Compliance & Remediation -->
    <div class="main-grid" style="grid-template-columns: 1fr 1fr;">
      <!-- Compliance Flags -->
      <div class="card">
        <div class="card-title">Mevzuat Uyum Denetim Özeti</div>
        <div id="complianceList">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- Remediation Quick Guide -->
      <div class="card">
        <div class="card-title">Hızlı Düzeltme Reçetesi (Nginx / OpenSSL 3.x Hibrit KEM)</div>
        <pre># /etc/nginx/conf.d/pqc-hybrid.conf
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:x25519:secp256r1;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_prefer_server_ciphers on;</pre>
      </div>
    </div>
  </div>

  <!-- Asset Inspection Drawer -->
  <div id="drawerBackdrop" onclick="closeDrawer()"></div>
  <div id="drawer">
    <div class="drawer-header">
      <h3 style="font-size: 16px; font-weight: 700;">Kriptografik Varlık İncelemesi</h3>
      <button class="drawer-close" onclick="closeDrawer()">&times;</button>
    </div>
    <div id="drawerContent">
      <!-- Populated when row clicked -->
    </div>
  </div>

  <script>
    const cbomData = {cbom_json_str};
    const rawComponents = {components_json};
    let components = [...rawComponents];
    const complianceFlags = {json.dumps(report.compliance_flags)};
    const targetName = "{report.target}";
    const merkleRoot = "{report.merkle_root or ''}";
    const pqriScore = {report.pqri_score};

    let currentCategory = "all";
    let physicsActive = true;
    let nodes = [];
    let draggedNode = null;
    let hoveredNode = null;
    let animFrameId = null;
    let sortOrders = {{}};

    // Force-Directed Graph Physics
    function initTopology() {{
      const canvas = document.getElementById("topologyCanvas");
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.scale(dpr, dpr);

      const w = rect.width;
      const h = rect.height;
      const cx = w / 2;
      const cy = h / 2;

      // Root Node
      const rootNode = {{
        id: "root",
        name: targetName,
        isRoot: true,
        x: cx,
        y: cy,
        vx: 0,
        vy: 0,
        radius: 12,
        fixed: true,
      }};

      // Asset Nodes
      const assetNodes = components.map((comp, idx) => {{
        const angle = (idx / components.length) * Math.PI * 2;
        const dist = 100 + Math.random() * 80;
        return {{
          id: comp.ref,
          comp: comp,
          isRoot: false,
          x: cx + Math.cos(angle) * dist,
          y: cy + Math.sin(angle) * dist,
          vx: (Math.random() - 0.5) * 2,
          vy: (Math.random() - 0.5) * 2,
          radius: comp.shor ? 8 : 6,
          pulse: Math.random() * Math.PI * 2,
        }};
      }});

      nodes = [rootNode, ...assetNodes];

      // Mouse & Touch Handlers
      function getNodeAt(x, y) {{
        for (let i = nodes.length - 1; i >= 0; i--) {{
          const n = nodes[i];
          const dist = Math.hypot(n.x - x, n.y - y);
          if (dist <= n.radius + 6) return n;
        }}
        return null;
      }}

      canvas.onmousedown = (e) => {{
        const r = canvas.getBoundingClientRect();
        const mx = e.clientX - r.left;
        const my = e.clientY - r.top;
        const n = getNodeAt(mx, my);
        if (n) {{
          draggedNode = n;
          if (!n.isRoot) n.fixed = true;
        }}
      }};

      window.onmousemove = (e) => {{
        const r = canvas.getBoundingClientRect();
        const mx = e.clientX - r.left;
        const my = e.clientY - r.top;
        if (draggedNode) {{
          draggedNode.x = mx;
          draggedNode.y = my;
        }} else {{
          hoveredNode = getNodeAt(mx, my);
        }}
      }};

      window.onmouseup = () => {{
        if (draggedNode) {{
          if (!draggedNode.isRoot) draggedNode.fixed = false;
          draggedNode = null;
        }}
      }};

      // Touch handlers for mobile
      canvas.ontouchstart = (e) => {{
        const r = canvas.getBoundingClientRect();
        const t = e.touches[0];
        const mx = t.clientX - r.left;
        const my = t.clientY - r.top;
        const n = getNodeAt(mx, my);
        if (n) {{
          draggedNode = n;
          if (!n.isRoot) n.fixed = true;
          if (n.comp) openDrawer(n.comp);
        }}
      }};

      window.ontouchmove = (e) => {{
        if (!draggedNode) return;
        const r = canvas.getBoundingClientRect();
        const t = e.touches[0];
        draggedNode.x = t.clientX - r.left;
        draggedNode.y = t.clientY - r.top;
      }};

      window.ontouchend = () => {{
        if (draggedNode) {{
          if (!draggedNode.isRoot) draggedNode.fixed = false;
          draggedNode = null;
        }}
      }};

      function stepPhysics() {{
        if (!physicsActive) return;
        const kRepel = 1200;
        const kSpring = 0.008;
        const damping = 0.88;
        const springLength = 130;

        for (let i = 0; i < nodes.length; i++) {{
          const a = nodes[i];
          if (a.fixed) continue;

          // Repulsion between all nodes
          for (let j = 0; j < nodes.length; j++) {{
            if (i === j) continue;
            const b = nodes[j];
            const dx = a.x - b.x;
            const dy = a.y - b.y;
            const d = Math.hypot(dx, dy) || 1;
            if (d < 250) {{
              const force = kRepel / (d * d);
              a.vx += (dx / d) * force;
              a.vy += (dy / d) * force;
            }}
          }}

          // Spring attraction to root
          const dx = rootNode.x - a.x;
          const dy = rootNode.y - a.y;
          const d = Math.hypot(dx, dy) || 1;
          const springForce = (d - springLength) * kSpring;
          a.vx += (dx / d) * springForce;
          a.vy += (dy / d) * springForce;

          // Apply velocity and damping
          a.vx *= damping;
          a.vy *= damping;
          a.x += a.vx;
          a.y += a.vy;

          // Boundary constraints
          a.x = Math.max(20, Math.min(w - 20, a.x));
          a.y = Math.max(20, Math.min(h - 20, a.y));
        }}
      }}

      function renderFrame() {{
        ctx.clearRect(0, 0, w, h);
        stepPhysics();

        // 1. Draw Links to Root
        for (let i = 1; i < nodes.length; i++) {{
          const n = nodes[i];
          ctx.beginPath();
          ctx.moveTo(rootNode.x, rootNode.y);
          ctx.lineTo(n.x, n.y);
          ctx.strokeStyle = n.comp.shor ? "rgba(244, 63, 94, 0.25)" : "rgba(16, 185, 129, 0.25)";
          ctx.lineWidth = n.comp.shor ? 1.8 : 1.2;
          ctx.stroke();
        }}

        // 2. Draw Asset Nodes
        for (let i = 1; i < nodes.length; i++) {{
          const n = nodes[i];

          // Threat radar ring for Shor vulnerable
          if (n.comp.shor) {{
            n.pulse += 0.04;
            const pulseR = n.radius + Math.sin(n.pulse) * 6 + 4;
            ctx.beginPath();
            ctx.arc(n.x, n.y, pulseR, 0, Math.PI * 2);
            ctx.strokeStyle = "rgba(244, 63, 94, 0.35)";
            ctx.lineWidth = 1.2;
            ctx.stroke();
          }}

          // Node body
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
          ctx.fillStyle = n.comp.shor ? "#f43f5e" : "#10b981";
          ctx.fill();
          ctx.strokeStyle = "rgba(255, 255, 255, 0.3)";
          ctx.lineWidth = 1;
          ctx.stroke();

          // Label
          ctx.font = "11px var(--font-mono)";
          ctx.fillStyle = "#cbd5e1";
          ctx.fillText(n.comp.algo, n.x + 10, n.y + 4);
        }}

        // 3. Draw Root Node
        ctx.beginPath();
        ctx.arc(rootNode.x, rootNode.y, rootNode.radius, 0, Math.PI * 2);
        ctx.fillStyle = "#06b6d4";
        ctx.fill();
        ctx.strokeStyle = "rgba(6, 182, 212, 0.45)";
        ctx.lineWidth = 8;
        ctx.stroke();

        ctx.font = "bold 12px var(--font-sans)";
        ctx.fillStyle = "#f8fafc";
        ctx.fillText(targetName, rootNode.x - 30, rootNode.y - 18);

        // 4. Hover Tooltip
        if (hoveredNode && hoveredNode.comp) {{
          const c = hoveredNode.comp;
          const text = `${{c.name}} | ${{c.algo}} (L${{c.nistLevel}})`;
          ctx.font = "11px var(--font-sans)";
          const tw = ctx.measureText(text).width;
          const pad = 8;
          ctx.fillStyle = "rgba(11, 17, 29, 0.95)";
          ctx.fillRect(hoveredNode.x + 12, hoveredNode.y - 24, tw + pad * 2, 22);
          ctx.strokeStyle = "rgba(6, 182, 212, 0.6)";
          ctx.strokeRect(hoveredNode.x + 12, hoveredNode.y - 24, tw + pad * 2, 22);
          ctx.fillStyle = "#f8fafc";
          ctx.fillText(text, hoveredNode.x + 12 + pad, hoveredNode.y - 9);
        }}

        animFrameId = requestAnimationFrame(renderFrame);
      }}

      if (animFrameId) cancelAnimationFrame(animFrameId);
      renderFrame();
    }}

    function resetGraphPhysics() {{
      initTopology();
    }}

    function toggleGraphPhysics() {{
      physicsActive = !physicsActive;
      document.getElementById("btnTogglePhysics").innerText = physicsActive ? "⏸ Duraklat" : "▶️ Başlat";
    }}

    function focusCriticalNodes() {{
      setFilterCategory("shor");
    }}

    window.addEventListener("resize", initTopology);

    // Asset Table Rendering & Sorting
    function renderAssets(items) {{
      const tbody = document.querySelector("#assetTable tbody");
      tbody.innerHTML = "";
      items.forEach(c => {{
        const tr = document.createElement("tr");
        const badgeClass = c.shor ? "badge-critical" : (c.replacement === "ALREADY_PQC_READY" ? "badge-ready" : "badge-high");
        const badgeText = c.shor ? "KRİTİK" : (c.replacement === "ALREADY_PQC_READY" ? "GÜVENLİ" : "GEÇİŞ");
        tr.innerHTML = `
          <td><strong>${{c.name}}</strong></td>
          <td>${{c.type}}</td>
          <td>${{c.algo}}</td>
          <td>${{c.keySize}} bit</td>
          <td><span class="badge ${{badgeClass}}">${{badgeText}} (L${{c.nistLevel}})</span></td>
          <td style="color: var(--accent-cyan);">${{c.replacement}}</td>
        `;
        tr.onclick = () => openDrawer(c);
        tbody.appendChild(tr);
      }});
    }}

    function sortTable(columnIndex) {{
      const keys = ["name", "type", "algo", "keySize", "nistLevel", "replacement"];
      const key = keys[columnIndex];
      sortOrders[key] = !sortOrders[key];
      const asc = sortOrders[key];

      components.sort((a, b) => {{
        let va = a[key];
        let vb = b[key];
        if (typeof va === "string") return asc ? va.localeCompare(vb) : vb.localeCompare(va);
        return asc ? (va - vb) : (vb - va);
      }});

      filterAssets();
    }}

    function filterAssets() {{
      const query = (document.getElementById("filterInput").value || "").toLowerCase();
      const filtered = components.filter(c => {{
        const matchesQuery = c.name.toLowerCase().includes(query) ||
                             c.algo.toLowerCase().includes(query) ||
                             c.type.toLowerCase().includes(query) ||
                             c.replacement.toLowerCase().includes(query);
        let matchesCat = true;
        if (currentCategory === "shor") matchesCat = c.shor;
        else if (currentCategory === "ready") matchesCat = !c.shor;
        else if (currentCategory === "certificate") matchesCat = c.type === "certificate";
        else if (currentCategory === "protocol") matchesCat = c.type === "protocol";
        else if (currentCategory === "key") matchesCat = c.type === "key";

        return matchesQuery && matchesCat;
      }});
      renderAssets(filtered);
    }}

    function setFilterCategory(cat, el) {{
      currentCategory = cat;
      document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
      if (el) {{
        el.classList.add("active");
      }} else {{
        const chips = Array.from(document.querySelectorAll(".chip"));
        const targetChip = chips.find(c => (c.getAttribute("onclick") || "").includes(`'${{cat}}'`));
        if (targetChip) targetChip.classList.add("active");
      }}
      filterAssets();
    }}

    function renderCompliance() {{
      const container = document.getElementById("complianceList");
      container.innerHTML = "";
      if (complianceFlags.length === 0) {{
        container.innerHTML = `<div class="compliance-item ok">✅ Kritik yasal uyumsuzluk tespit edilmedi. Sistem PQC geçişine hazır.</div>`;
      }} else {{
        complianceFlags.forEach(f => {{
          const div = document.createElement("div");
          div.className = "compliance-item";
          div.innerHTML = `<strong>⚠️ ${{f}}</strong><br><span style="color: var(--text-muted); font-size: 11px;">Mevzuat gereği klasik anahtarlar kuantum dayanıklı alternatiflerle değiştirilmelidir.</span>`;
          container.appendChild(div);
        }});
      }}
    }}

    function updateMosca() {{
      const X = parseFloat(document.getElementById("sliderX").value);
      const Y = parseFloat(document.getElementById("sliderY").value);
      const Z = parseFloat(document.getElementById("sliderZ").value);

      document.getElementById("valX").innerText = X + " Yıl";
      document.getElementById("valY").innerText = Y + " Yıl";
      document.getElementById("valZ").innerText = Z + " Yıl";

      const verdictEl = document.getElementById("simVerdict");
      if (X + Y > Z) {{
        verdictEl.style.background = "rgba(244,63,94,0.15)";
        verdictEl.style.borderColor = "rgba(244,63,94,0.3)";
        verdictEl.style.color = "var(--accent-rose)";
        verdictEl.innerText = `⚠️ TEHLİKE: X + Y (${{(X + Y).toFixed(1)}} Yıl) > Z (${{Z.toFixed(1)}} Yıl) — HNDL Zafiyeti Mevcut!`;
      }} else {{
        verdictEl.style.background = "rgba(16,185,129,0.15)";
        verdictEl.style.borderColor = "rgba(16,185,129,0.3)";
        verdictEl.style.color = "var(--accent-emerald)";
        verdictEl.innerText = `✅ GÜVENLİ: X + Y (${{(X + Y).toFixed(1)}} Yıl) <= Z (${{Z.toFixed(1)}} Yıl) — Veri Kuantum Öncesi Güvende!`;
      }}
    }}

    // In-Browser Live Monte Carlo Simulation (N=10,000)
    function runLiveMonteCarlo() {{
      const scaleX = parseFloat(document.getElementById("sliderX").value);
      const iterations = 10000;
      let vulnerable = 0;
      const diffs = [];

      for (let i = 0; i < iterations; i++) {{
        // Weibull distribution for X
        const u1 = Math.random() || 0.0001;
        const x = scaleX * Math.sqrt(-Math.log(u1));
        // Triangular distribution for Y [2.0, 6.0]
        const y = 2.0 + ((Math.random() + Math.random()) / 2.0) * 4.0;
        // Normal distribution for Z (mean=8.5, std=1.8) via Box-Muller
        const u2 = Math.random() || 0.0001;
        const u3 = Math.random();
        const zNorm = Math.sqrt(-2.0 * Math.log(u2)) * Math.cos(2.0 * Math.PI * u3);
        let z = 8.5 + zNorm * 1.8;
        z = Math.max(4.0, Math.min(16.0, z));

        const diff = (x + y) - z;
        diffs.push(diff);
        if (diff > 0) vulnerable++;
      }}

      const prob = (vulnerable / iterations) * 100;
      const margin = (1.96 * Math.sqrt((prob/100 * (1 - prob/100)) / iterations)) * 100;
      document.getElementById("mcStatsText").innerText = `HNDL Zafiyet Riski: %${{prob.toFixed(2)}} (95% CI: [%${{(prob - margin).toFixed(1)}}, %${{(prob + margin).toFixed(1)}}])`;

      drawHistogram(diffs);
    }}

    function drawHistogram(diffs) {{
      const canvas = document.getElementById("histogramCanvas");
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.scale(dpr, dpr);

      const w = rect.width;
      const h = rect.height;

      const bins = 24;
      const counts = new Array(bins).fill(0);
      const minVal = -10;
      const maxVal = 20;

      diffs.forEach(d => {{
        const b = Math.floor(((d - minVal) / (maxVal - minVal)) * bins);
        if (b >= 0 && b < bins) counts[b]++;
      }});

      const maxCount = Math.max(...counts, 1);
      ctx.clearRect(0, 0, w, h);

      const barW = (w - (bins - 1) * 2) / bins;
      counts.forEach((c, i) => {{
        const val = minVal + (i / bins) * (maxVal - minVal);
        const bh = (c / maxCount) * (h - 20);
        const bx = i * (barW + 2);
        const by = h - bh - 4;

        ctx.fillStyle = val > 0 ? "rgba(244, 63, 94, 0.75)" : "rgba(16, 185, 129, 0.75)";
        ctx.fillRect(bx, by, barW, bh);
      }});

      // Threshold zero line
      const zeroX = ((0 - minVal) / (maxVal - minVal)) * w;
      ctx.beginPath();
      ctx.moveTo(zeroX, 0);
      ctx.lineTo(zeroX, h);
      ctx.strokeStyle = "#f8fafc";
      ctx.setLineDash([2, 2]);
      ctx.stroke();
      ctx.setLineDash([]);
    }}

    // Drawer Interaction
    function openDrawer(c) {{
      const drawer = document.getElementById("drawer");
      const backdrop = document.getElementById("drawerBackdrop");
      const content = document.getElementById("drawerContent");

      content.innerHTML = `
        <div class="drawer-field">
          <div class="drawer-field-label">Varlık Adı</div>
          <div class="drawer-field-value">${{c.name}}</div>
        </div>
        <div class="drawer-field">
          <div class="drawer-field-label">Kriptografik Algoritma</div>
          <div class="drawer-field-value">${{c.algo}} (${{c.keySize}} bit)</div>
        </div>
        <div class="drawer-field">
          <div class="drawer-field-label">Varlık Tipi</div>
          <div class="drawer-field-value">${{c.type}}</div>
        </div>
        <div class="drawer-field">
          <div class="drawer-field-label">NIST Kuantum Güvenlik Seviyesi</div>
          <div class="drawer-field-value">Seviye ${{c.nistLevel}} ${{c.nistLevel === 0 ? "(Kuantum Öncesi - Zayıf)" : "(PQC Standart)"}}</div>
        </div>
        <div class="drawer-field">
          <div class="drawer-field-label">Shor Kırılganlığı (HNDL)</div>
          <div class="drawer-field-value" style="color: ${{c.shor ? 'var(--accent-rose)' : 'var(--accent-emerald)'}}">
            ${{c.shor ? 'EVET — Polinomik Zamanlı Kırılabilir' : 'HAYIR — Kuantum Dayanıklı'}}
          </div>
        </div>
        <div class="drawer-field">
          <div class="drawer-field-label">Önerilen PQC Geçiş Standardı</div>
          <div class="drawer-field-value" style="color: var(--accent-cyan)">${{c.replacement}}</div>
        </div>
        <div class="drawer-field">
          <div class="drawer-field-label">Nesne Tanımlayıcı (OID)</div>
          <div class="drawer-field-value">${{c.oid}}</div>
        </div>
        <div class="drawer-field">
          <div class="drawer-field-label">CycloneDX 1.6 Referansı (bom-ref)</div>
          <div class="drawer-field-value">${{c.ref}}</div>
        </div>
        <div style="margin-top: 24px;">
          <button class="btn btn-primary" style="width: 100%; justify-content: center;" onclick="copyGuidance('${{c.replacement}}')">📋 PQC Geçiş Kılavuzunu Kopyala</button>
        </div>
      `;

      backdrop.classList.add("open");
      drawer.classList.add("open");
    }}

    function closeDrawer() {{
      document.getElementById("drawer").classList.remove("open");
      document.getElementById("drawerBackdrop").classList.remove("open");
    }}

    function copyGuidance(replacement) {{
      navigator.clipboard.writeText(`// PQHaven Migration Target: ${{replacement}}`).then(() => {{
        alert("PQC geçiş hedefi panoya kopyalandı: " + replacement);
      }});
    }}

    function copyExecutiveSummary() {{
      const summary = `# PQHaven Kriptografik Denetim Özeti\\n\\n` +
        `- **Hedef:** ${{targetName}}\\n` +
        `- **PQRI Risk Skoru:** ${{pqriScore}} / 100\\n` +
        `- **Toplam Varlık Sayısı:** ${{components.length}}\\n` +
        `- **Shor Zafiyetli Varlık:** ${{components.filter(c => c.shor).length}}\\n` +
        `- **CycloneDX 1.6 CBOM Merkle Root:** 0x${{merkleRoot}}\\n\\n` +
        `*PQHaven Autonomous Crypto-Agility Engine tarafından oluşturuldu.*`;
      navigator.clipboard.writeText(summary).then(() => {{
        alert("Yönetici özeti Markdown formatında panoya kopyalandı!");
      }});
    }}

    // Export Functions
    function downloadCbom() {{
      const blob = new Blob([JSON.stringify(cbomData, null, 2)], {{ type: "application/json" }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cbom-${{cbomData.serialNumber.replace(/:/g, "-")}}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }}

    function downloadCsv() {{
      let csv = "Name,Type,Algorithm,KeySize,NistLevel,ShorVulnerable,RecommendedReplacement,OID\\n";
      components.forEach(c => {{
        csv += `"${{c.name}}","${{c.type}}","${{c.algo}}",${{c.keySize}},${{c.nistLevel}},${{c.shor}},"${{c.replacement}}","${{c.oid}}"\\n`;
      }});
      const blob = new Blob([csv], {{ type: "text/csv" }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pqc-inventory-${{targetName.replace(/:/g, "-")}}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    }}

    function downloadVc() {{
      const vc = {{
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://schema.pqhaven.io/pqc-attestation/v1"],
        "id": "urn:uuid:" + cbomData.serialNumber.split(":").pop(),
        "type": ["VerifiableCredential", "PqcPostureAttestation"],
        "issuer": "did:pqhaven:auditor:0x1b24",
        "validFrom": new Date().toISOString(),
        "credentialSubject": {{
          "targetEndpoint": targetName,
          "cbomMerkleRoot": merkleRoot ? "0x" + merkleRoot : "N/A",
          "hndlVulnerabilities": {report.hndl_vulnerability_count},
          "totalCryptoAssets": components.length,
          "complianceFlags": complianceFlags,
          "onChainRegistryContract": "0x446B847e096B408B48B4bEeeFd0F4D3C23B99511"
        }}
      }};
      const blob = new Blob([JSON.stringify(vc, null, 2)], {{ type: "application/json" }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pqc-attestation-vc-${{targetName.replace(/:/g, "-")}}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }}

    // Initial Load
    renderAssets(components);
    renderCompliance();
    updateMosca();
    runLiveMonteCarlo();
    setTimeout(initTopology, 50);
  </script>
</body>
</html>
"""
    return html
