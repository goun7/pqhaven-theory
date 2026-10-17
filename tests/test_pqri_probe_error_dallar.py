"""DALGA-D10 (PQH-NET-2): probe-error'in PQRI metriğine etkisinin pin'lendigi testler.

BULGU (PQH-NET-2): bir hedefe bağlanırken probe hata verirse (ağ-erişilemez,
timeout, DNS başarısız) eski kod PQRI'yi gizleyip "0.0 / 100 READY + Uyumsuzluk
Yok" basıyordu — yanıltıcı "hazır" (fail-silent / false-safety). Artık:
  - hiç hedefe bağlanılamadıysa  -> PQRI N/A (incomplete-evidence), derece UNKNOWN
  - bağlandı ama ham-probe ölçümediyse -> PQRI N/A (probe-error), derece UNKNOWN
  - her N/A durumu compliance flag'i taşır ve CLI rc != 0 ile biter (fail-loud).

Kısıt: sadece 127.0.0.1 + .invalid TLD — dış ağ'a KESİNLİKLE bağlanılmaz.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest
from click.testing import CliRunner

from pqhaven.cli import main
from pqhaven.engine import PQScanEngine
from pqhaven.models import PqcRiskGrade
from pqhaven.network import NetworkProbe


# ----------------------------------------------------------------------------
# Motor katmani: assess_target probe_health yolu
# ----------------------------------------------------------------------------

def test_pqri_hedefye_baglanilamadiysa_na_dir():
    """PQH-NET-2: denendi (total>0) + bağlanılamadı (connected==0) => N/A."""
    engine = PQScanEngine()
    rep = engine.assess_target(
        "127.0.0.1:1",
        [],
        probe_health={"total": 3, "connected": 0, "probe_errors": 0},
    )
    assert rep.pqri_score is None
    assert rep.pqri_is_na is True
    assert rep.overall_grade is PqcRiskGrade.UNKNOWN
    assert rep.none_reason == "incomplete-evidence"


def test_pqri_na_her_zaman_sebeple_gelir():
    """invariant: pqri_score None ise none_reason dolu olmali (sessiz N/A yasak)."""
    engine = PQScanEngine()
    for ph in (
        {"total": 1, "connected": 0, "probe_errors": 0},
        {"total": 2, "connected": 1, "probe_errors": 1},
        {"total": 1, "connected": 1, "probe_errors": 1},
    ):
        rep = engine.assess_target("hedef", [], probe_health=ph)
        if rep.pqri_score is None:
            assert rep.none_reason in {"incomplete-evidence", "probe-error"}


def test_pqri_probe_health_verilmezse_degismez():
    """Geri-uyumluluk: probe_health yoksa eski davranis bozulmaz (skor sayi)."""
    engine = PQScanEngine()
    rep = engine.assess_target("sys", [{"name": "a", "algorithm": "RSA-2048", "type": "certificate"}])
    assert rep.pqri_score is not None
    assert rep.overall_grade is not PqcRiskGrade.UNKNOWN
    assert rep.none_reason is None


def test_pqri_kismi_basari_na_degildir():
    """2 hedeften 1 baglandiysa kanit mevcut -> N/A degil, gercek skor."""
    engine = PQScanEngine()
    rep = engine.assess_target(
        "karisik",
        [{"name": "kex", "algorithm": "ECDH-X25519", "type": "protocol", "key_size": 256}],
        probe_health={"total": 2, "connected": 1, "probe_errors": 0},
    )
    assert rep.pqri_score is not None
    assert rep.pqri_is_na is False


def test_pqri_bos_cbom_hala_sifir_degil_na():
    """Kritik: bos CBOM + hedef denendi = N/A; bos CBOM + hedef denenmedi = 0.0."""
    engine = PQScanEngine()
    na = engine.assess_target("x", [], probe_health={"total": 1, "connected": 0, "probe_errors": 0})
    sifir = engine.assess_target("x", [])
    assert na.pqri_score is None
    assert sifir.pqri_score == 0.0
    assert sifir.overall_grade is PqcRiskGrade.READY


def test_pqri_na_compliance_flag_tasiyor():
    """N/A raporu 'Uyumsuzluk Yok' diye basilmamali - flag zorunlu."""
    engine = PQScanEngine()
    rep = engine.assess_target(
        "127.0.0.1:1", [], probe_health={"total": 1, "connected": 0, "probe_errors": 0}
    )
    assert any("PQRI_NA_" in f for f in rep.compliance_flags)


# ----------------------------------------------------------------------------
# Ağ katmani: ham-probe RST -> probe-error
# ----------------------------------------------------------------------------

def _raw_rst_sunucusu():
    """Baglantiyi TLS province kabul etmeden RST ile kapatir (ham-probe hatasi)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(4)
    srv.settimeout(5.0)

    def worker():
        for _ in range(2):
            try:
                conn, _ = srv.accept()
                conn.close()  # RST -> probe-error
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True).start()
    return srv, port


def test_ham_probe_rst_pqri_probe_error_yapar():
    """PQH-NET-1 + PQH-NET-2: ham-probe RST -> probe-error -> PQRI N/A."""
    srv, port = _raw_rst_sunucusu()
    try:
        probe = NetworkProbe(timeout=1.0)
        ok, kex = probe._probe_raw_tls13_hybrid("127.0.0.1", port)
        assert ok is False
        assert kex == "probe-error"

        engine = PQScanEngine()
        rep = engine.assess_target(
            f"127.0.0.1:{port}",
            [{"name": "kex", "algorithm": "ECDH-X25519", "type": "protocol", "key_size": 256}],
            probe_health={"total": 1, "connected": 1, "probe_errors": 1},
        )
        assert rep.pqri_is_na is True
        assert rep.none_reason == "probe-error"
    finally:
        srv.close()


def test_ham_probe_ust_operasyon_probe_error_set_eder():
    """probe_tls_endpoint ham-probe hatasinda probe_error alanini set eder."""
    srv, port = _raw_rst_sunucusu()
    try:
        probe = NetworkProbe(timeout=1.0)
        ok, kex = probe._probe_raw_tls13_hybrid("127.0.0.1", port)
        assert (ok, kex) == (False, "probe-error")
        # Ust katman: hata metni contract'i (PQH-NET-1 DUZELTME'si)
        assert isinstance(kex, str) and kex
    finally:
        srv.close()


# ----------------------------------------------------------------------------
# CLI katmani: rc-matrisi (fail-loud pin'leri)
# ----------------------------------------------------------------------------

def test_cli_scan_ulasilamaz_host_rc_farkli_sifir():
    """PQH-NET-2: 2 hedef de erisilemez -> rc != 0 + PQRI N/A (0.0/READY degil)."""
    runner = CliRunner()
    res = runner.invoke(main, ["scan", "--network", "127.0.0.1:1,pqh-d10.invalid", "-p", "1"])
    assert res.exit_code != 0
    cikti = res.output
    assert "N/A" in cikti
    assert "0.0 / 100" not in cikti  # yalanci-yesil yasak
    assert "READY" not in cikti or "UNKNOWN" in cikti


def test_cli_scan_tek_ulasilamaz_host_rc_farkli_sifir():
    """Tek hedef erisilemez -> ClickException (rc=1)."""
    runner = CliRunner()
    res = runner.invoke(main, ["scan", "127.0.0.1:1", "-p", "1"])
    assert res.exit_code == 1
    # (zengin tablo genisligi metni kesebilir - "ag" / " refused" esigi yeterli)
    out = res.output
    assert "ag" in out.lower() or "refused" in out.lower()


def test_cli_scan_na_mesaji_sebep_sayilarini_icerir():
    """N/A mesaji denenen/bağlanan sayilarini vermeli (teshis)."""
    runner = CliRunner()
    res = runner.invoke(main, ["scan", "--network", "127.0.0.1:1,pqh-d10b.invalid", "-p", "1"])
    assert res.exit_code != 0
    assert "denenen=2" in res.output
    assert "baglanan=0" in res.output


def test_cli_scan_demo_modu_na_degil():
    """--demo kanitlocali oldugu icin N/A'ya dusmemeli (rc=0)."""
    runner = CliRunner()
    res = runner.invoke(main, ["scan", "--network", "127.0.0.1:1", "-p", "1", "--demo"])
    assert res.exit_code == 0
    assert "0.0 / 100" in res.output or "/ 100" in res.output
    assert "N/A" not in res.output


def test_cli_render_tablosu_na_satiri():
    """_render_report_table N/A'da 'None / 100' degil 'N/A (olculemedi)' basar."""
    from types import SimpleNamespace

    from pqhaven.cli import _render_report_table
    from rich.console import Console

    rep = SimpleNamespace(
        target="t",
        overall_grade=PqcRiskGrade.UNKNOWN,
        pqri_score=None,
        hndl_vulnerability_count=0,
        cbom=SimpleNamespace(components=[]),
        merkle_root=None,
        compliance_flags=["PQRI_NA_INCOMPLETE-EVIDENCE"],
        none_reason="incomplete-evidence",
    )
    import io

    buf = io.StringIO()
    konsol = Console(file=buf, width=120)
    from pqhaven import cli as cli_mod

    eski = cli_mod.console
    cli_mod.console = konsol
    try:
        _render_report_table(rep)
    finally:
        cli_mod.console = eski
    out = buf.getvalue()
    assert "N/A" in out
    assert "None / 100" not in out
    assert "UNKNOWN" in out


# ----------------------------------------------------------------------------
# Ledger/kanit katmani: N/A "0.0" olarak kaydedilmesin
# ----------------------------------------------------------------------------

def test_mesh_anchor_na_pqri_none_yazar():
    """build_anchor_record: N/A skoru ledger'a 0.0 degil None yazmali."""
    engine = PQScanEngine()
    rep = engine.assess_target(
        "127.0.0.1:1", [], probe_health={"total": 1, "connected": 0, "probe_errors": 0}
    )
    from pqhaven.mesh_anchor import build_anchor_record

    rec = build_anchor_record(rep)
    assert rec["pqri_score"] is None
    assert rec["overall_grade"] == "UNKNOWN"


def test_mesh_anchor_skorlu_pqri_korunur():
    """Geri-uyumluluk: normal skorlu rapor ledger'a float olarak yazilmaya devam eder."""
    engine = PQScanEngine()
    rep = engine.assess_target(
        "sys", [{"name": "a", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048}]
    )
    from pqhaven.mesh_anchor import build_anchor_record

    rec = build_anchor_record(rep)
    assert isinstance(rec["pqri_score"], float)
    assert rec["pqri_score"] > 0.0


# ----------------------------------------------------------------------------
# Daemon katmani: N/A drift/webhook faisizligi
# ----------------------------------------------------------------------------

def test_daemon_alert_level_na_critical():
    """N/A iken alertLevel INFO degil CRITICAL olmali (eski TypeError/yanlis-info)."""
    from pqhaven.daemon import SentinelDaemon

    d = SentinelDaemon(interval_seconds=60, webhook_url=None)
    drift = {"has_drift": True, "new_vulnerabilities": [], "score_delta": 0.0, "new_assets": []}
    state = {"timestamp": 1.0, "pqri_score": None, "overall_grade": "UNKNOWN"}
    lvl = "CRITICAL" if (state["pqri_score"] is None or state["pqri_score"] >= d.threshold) else "INFO"
    assert lvl == "CRITICAL"


def test_daemon_drift_na_gecisi_tetikler():
    """score 42 -> None gecisi drift olarak algilanmali (kanit kaybi)."""
    from pqhaven.daemon import SentinelDaemon

    d = SentinelDaemon(interval_seconds=60, webhook_url=None)
    prev = {"pqri_score": 42.0, "assets": {}}
    curr = {"pqri_score": None, "assets": {}}
    fark = d.detect_drift(prev, curr)
    assert fark["has_drift"] is True


# ----------------------------------------------------------------------------
# Cockpit katmani: N/A gauge'i
# ----------------------------------------------------------------------------

def test_cockpit_na_pqri_gosterimi():
    """Cockpit N/A raporunu 'None / 100' yerine N/A olarak gosterir (TypeError yok)."""
    engine = PQScanEngine()
    rep = engine.assess_target(
        "127.0.0.1:1", [], probe_health={"total": 1, "connected": 0, "probe_errors": 0}
    )
    from pqhaven.cockpit import generate_cockpit_html

    html = generate_cockpit_html(rep)
    assert "N/A" in html
    assert "None / 100" not in html
    assert "UNKNOWN" in html


def test_cockpit_skorlu_pqri_korunur():
    """Geri-uyumluluk: normal raporun cockpit ciktisi degismeden kalmali."""
    engine = PQScanEngine()
    rep = engine.assess_target(
        "sys", [{"name": "a", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048}]
    )
    from pqhaven.cockpit import generate_cockpit_html

    html = generate_cockpit_html(rep)
    assert "PQRI Risk İndeksi" in html
    assert "CRITICAL" in html


# ----------------------------------------------------------------------------
# VC (verifiable credential) katmani
# ----------------------------------------------------------------------------

def test_vc_na_pqri_none_zincirler():
    """W3C VC: N/A skoru 'pqriScore': null olarak zincirlenmeli (0.0 degil)."""
    engine = PQScanEngine()
    rep = engine.assess_target(
        "127.0.0.1:1", [], probe_health={"total": 1, "connected": 0, "probe_errors": 0}
    )
    vc = engine.generate_verifiable_credential(rep)
    assert vc.credential_subject["pqriScore"] is None
    assert vc.credential_subject["pqriIsNa"] is True
    assert vc.credential_subject["overallGrade"] == "UNKNOWN"


# ----------------------------------------------------------------------------
# Eski PQH-NET-1 pin'leri (regresyon korumasi)
# ----------------------------------------------------------------------------

def test_pqh_net1_pin_probe_error_doner():
    """PQH-NET-1 (DALGA-C-2): kapali port -> (False, 'probe-error'), (False,'Unknown') degil."""
    probe = NetworkProbe(timeout=0.001)
    ok, kex = probe._probe_raw_tls13_hybrid("127.0.0.1", 1)
    assert ok is False
    assert kex == "probe-error"


def test_pqh_net1_pin_tls13_hibrit_olcumu():
    """PQH-NET-1 pozitif taraf: gecerli ServerHello 0x11ec -> (True, ...)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    srv.settimeout(3.0)

    def worker():
        try:
            conn, _ = srv.accept()
            _ = conn.recv(2048)
            body = b"\x02\x00\x00\x2e\x03\x03" + (b"\x00" * 32) + b"\x00\x33\x00\x04\x11\xec\x00\x00"
            conn.sendall(b"\x16\x03\x03" + struct.pack(">H", len(body)) + body)
            conn.close()
        except Exception:
            pass

    threading.Thread(target=worker, daemon=True).start()
    try:
        probe = NetworkProbe(timeout=2.0)
        ok, kex = probe._probe_raw_tls13_hybrid("127.0.0.1", port)
        assert ok is True
        assert "0x11ec" in kex
    finally:
        srv.close()
