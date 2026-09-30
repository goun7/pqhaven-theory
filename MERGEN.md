# 🧠 MERGEN PRELUDE — 80-PQHaven
_Üretim: 2026-09-16T17:40:13.159941+00:00 · 12 dosya · 2324 satır_

## 1. BÜTÜNSEL PROJE HARİTASI
Her dosya tek satırda: yol (satır sayısı) — amaç — ana semboller. Detay için dosyayı doğrudan oku.

# 📦 Proje Haritası: 80-PQHaven
_Üretim: 2026-09-16T17:40:13+00:00_
_Toplam 12 dosya · 2324 satır · harita 12 dosyayı listeler_

## . (1 dosya, 30 satır)
- pyproject.toml (30s)

## src/pqhaven (7 dosya, 1674 satır)
- __init__.py (3s) — PQHaven: Autonomous Cryptographic Bill of Materials (CBOM) Discovery & Post-Quantum Migration Decision Engine.
- cli.py (311s) — PQHaven CLI Interface (pqscan). | main, scan, probe_ssh, scan_dir, serve, _render_report_table
- cockpit.py (639s) — PQHaven Executive Cockpit & Interactive Telemetry HTML Generator. | generate_cockpit_html
- engine.py (137s) — PQHaven Core Discovery & Migration Analytics Engine. | PQScanEngine
- models.py (95s) — Data models and risk calculation for PQHaven. | PqcRiskGrade, CryptoAssetType, CryptoProperties, CryptoComponent, CycloneDxCbom, AssessmentReport, calculate_mosca_pqri, grade_pqri
- network.py (273s) — Real Network TLS & SSH Cryptographic Socket Probing Engine. | NetworkProbe
- scanner.py (216s) — Local Filesystem, Keystore, and Dependency Manifest Scanner. | LocalScanner

## tests (4 dosya, 620 satır)
- test_cli.py (210s) — Tests for pqscan CLI commands using Click CliRunner. | test_cli_version, test_cli_scan_dir_command, test_cli_scan_network_fallback, test_cli_ssh_command, test_cli_scan_connected_endpoint, test_cli_ssh_connected_endpoint, test_cli_serve_command
- test_core.py (70s) — Comprehensive tests for PQHaven core models, engine, and Mosca equations. | test_mosca_pqri_calculation_and_grading, test_engine_assessment_with_legacy_and_pqc, test_engine_all_pqc_ready
- test_network_and_cockpit.py (231s) — Tests for network probing logic (TLS & SSH) and HTML cockpit generation. | test_network_probe_parse_certificate, test_ssh_probe_handshake, test_cockpit_html_generation, test_network_probe_ecdsa_and_ed25519, test_tls_probe_local_ssl_server, test_ssh_probe_error_branches
- test_scanner.py (109s) — Tests for local filesystem, certificate, and dependency scanning. | test_local_scanner_with_real_files, test_scanner_formats_and_edge_cases


## 2. AKTİF KURALLAR (prehook)
⚙️ [USER PERSONA & RULES]: preferred_lang=Python 3.12
🛡️ [ACTIVE ARCHITECTURAL RULES (SANDWICH ATTENTION MASKED)]:
  • Overnight Mining Cycle 1 Completed -> Successfully ingested multi-domain patterns from AI, Game Engine (ECS), HFT, and RTOS. Tot...
  • [MINER AST] process Sub-Routine (Function Routine) ->  • Function routine process
 [... 3 detailed implementation lines condensed]...
  • feat(parsi/KOL): shadow-learn scam-vetoed KOL calls in PAPER (learn real hit-rate) ->  • Q3: a trusted KOL's call was hard-dropped by the scouter scam-veto (Satori-P0-12), so w...
  • [MINER AST] AsyncWorker Architecture Component (Class Architecture) ->  • Class definition for AsyncWorker
 [... 3 detailed implementation lines condensed]...
  • transkript-çapraz-bağ: ders-kapsamı-dışı-kalmış-bilgi (distill-kazanı) -> This session file `b358c7e6` is the current live session (it contains my own messages). Th...

## 🧬 AKTİF SKİLLER (kristalize — MAKİNE-GENELİ, proje-kapsamı-değil)
- `10000-araca-araliginda-artefaktir-ayri` [CHAMPION] · 566 kullanım · son 2026-09-16
- `mergen-memory` [CHAMPION] · 21 kullanım · son 2026-09-16
- `mergen-router` [CHAMPION] · 20 kullanım · son 2026-09-16
- `mergen-proof` [CHAMPION] · 20 kullanım · son 2026-09-16
- `mergen-sandbox` [CHAMPION] · 20 kullanım · son 2026-09-16
- `10000-araca-araliginda-artefaktir-ayrilamiyordu` [CHAMPION] · 20 kullanım · son 2026-09-16
- `100sn-37sn-acaba-alani-allforceorders` [CHAMPION] · 20 kullanım · son 2026-09-16
- `100sn-37sn-alani-allforceorders-backtest` [CHAMPION] · 20 kullanım · son 2026-09-16
- `10dk-1800sn-2026-30dk-30dkda` [CHAMPION] · 20 kullanım · son 2026-09-16
- `1111-1381-alma-arkhon-arkhon_score_gate_explore` [CHAMPION] · 20 kullanım · son 2026-09-16
- `1136-1221-2026-25000-505k` [CHAMPION] · 20 kullanım · son 2026-09-16
- `1178-1204-1238-3134-4kelly` [CHAMPION] · 20 kullanım · son 2026-09-16

## ⏭ SON AKTİF GÖREV (kaldığın yerden devam)
- **karne --json** (oturum `osrun-20260914-134942`, 2026-09-14T13:49:42.372785+00:00)
- İlgili bellekler: #3700, #569, #3883, #3850, #3674, #3670
- Devam: `mergen_memory.py --project <ad> os resume osrun-20260914-134942`

## 3. SON DERSLER
- **CycloneDX 1.6 CBOM serialization and TLS test socket hang** [pending · kanıt: kanıt yok]
  → Pydantic model_dump_json(by_alias=True) ensures spec-compliant camelCase/hyphenated keys; server-side mock TLS socket must avoid blocking sconn.recv(1024) durin
- **First live citation measurement through an OpenAI-compatible gateway (api.atria-asi.ai/v1) produced two false 'ölçülemed** [pending · kanıt: kanıt yok]
  → Normalize provider base URLs before appending version paths: strip trailing slash, and if the URL already ends with '/v1' strip it so /v1 is appended exactly on
- **80-PQHaven tam kapsamlı derin audit, SSH RFC 4253 canlı probu ve 11/11 test mühürü** [pending · kanıt: kanıt yok]
  → SSH transport probu eklendi, JKS/PKCS12 analizi tamamlandı, Canvas topoloji grafı entegre edildi, tüm CLI ve test suitleri 11/11 PASS ile mühürlendi.
- **80-PQHaven teknik borç ve mock temizliği, canlı ağ probu, UI/UX kokpit ve 9/9 PASS test kanıtı** [pending · kanıt: kanıt yok]
  → Simüle edilmiş mock veriler kaldırıldı; gerçek TLS soket ve X.509 ayrıştırıcı (NetworkProbe), yerel kod/bağımlılık tarayıcı (LocalScanner), lüks standalone HTML
- **80-PQHaven kağıt üzerinde ve referans mimaride 100/100 mükemmeliyet kapanışı** [pending · kanıt: kanıt yok]
  → PQHAVEN.md v16.0 standardına çıkarıldı (Teorem 1-4 ispatları, 20 PQC arşetipi, Monte Carlo, W3C VC, DSL EBNF), pyproject.toml, PQHavenRegistry.sol ve pqscan CLI
- **80-PQHaven 4 parça dağınık md dokümanı ve eksik PQC FIPS standartları** [pending · kanıt: kanıt yok]
  → Tüm dokümanlar tek kanonik PQHAVEN.md monografında birleştirildi, eski 4 dosya silindi, NIST FIPS 203/204/205, Regev 2023, CycloneDX 1.6 CBOM ve 3 portföy pilot
- **Invalidation Contracts (arxiv:2609.00243): pack'ler content_hash TAŞIMIYORDU — tüketici dersin bayatladığını sonraki tur** [pending · kanıt: kanıt yok]
  → (1) generate_context_pack her derse contract damgası basar: 'stale-if-hash-changes:<8hex>'; hash-yok → '?' (boş = bilinmez, uydurma-hash yok). (2) report_memory
- **Autonomous lead verification picked up fake evidence from real pages: CSS unicode-range 'U+0302-0303' matched as phone '** [pending · kanıt: kanıt yok]
  → Harden extraction with evidence guards: phone regex needs negative lookbehind (?<![A-Za-z0-9]) before '+' plus 7-15 ITU digit range; email filter rejects asset 
---
_Bu dosya mergen_memory.py prelude komutuyla otomatik üretilir; elle düzenleme üzerine yazılır._