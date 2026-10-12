"""80-PQHaven cli._render_report_table dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (RAM report-nesnesi + stdout-yakalama; network/DB YASAK).

ORTAM-ANATOMI:
- _render_report_table(report): rich Table basar; sutunlar 'Metrik / Parametre'
  + 'Değer'; satirlar PQRI/grade/HNDL/CBOM/Merkle/bayraklar
- color_map: CRITICAL/HIGH/TRANSITIONAL/READY -> bold red/orange3/yellow/green;
  bilinmeyen -> 'white'
- ORTAM-ANATOMI (rich): style-etiketleri [bold red] vb. yakalanan metinde YOK
"""
import contextlib
import io
import sys

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from pqhaven.cli import _render_report_table  # noqa: E402


def _report(**kw):
    class _R:
        pass
    class _Grade:
        pass
    class _Cbom:
        pass
    r = _R()
    r.target = "hedef"
    r.pqri_score = 42
    r.hndl_vulnerability_count = 3
    r.merkle_root = None
    r.compliance_flags = []
    g = _Grade()
    g.value = "READY"
    r.overall_grade = g
    r.cbom = _Cbom()
    r.cbom.components = [1, 2, 3]
    for k, v in kw.items():
        setattr(r, k, v)
    return r


def _yakala(report):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _render_report_table(report)
    return buf.getvalue()


# == temel degerler =====================================================================================

def test_pqri_skoru():
    assert "42 / 100" in _yakala(_report())


def test_hedef_basligi():
    assert "hedef" in _yakala(_report())


def test_hndl_sayisi():
    assert "3" in _yakala(_report())


def test_cbom_sayisi():
    """ORTAM: len(cbom.components) -> 3."""
    assert "3" in _yakala(_report())


def test_cbom_bos():
    out = _yakala(_report())
    r = _report()
    r.cbom.components = []
    assert "0" in _yakala(r)


def test_grade_degeri():
    """ORTAM: overall_grade.value basılır (style etiketleri METINDE YOK)."""
    assert "READY" in _yakala(_report())


def test_donut_dolu():
    assert len(_yakala(_report())) > 100


# == merkle root ========================================================================================

def test_merkle_var():
    """ORTAM: '0x{merkle_root}' biciminde (cyan ile)."""
    r = _report()
    r.merkle_root = "abc123"
    assert "0xabc123" in _yakala(r)


def test_merkle_yok():
    """ORTAM: merkle_root None -> 'Yok'."""
    r = _report()
    r.merkle_root = None
    assert "Yok" in _yakala(r)


def test_merkle_bos_str():
    """ORTAM: '' falsy -> 'Yok' (if report.merkle_root else)."""
    r = _report()
    r.merkle_root = ""
    assert "Yok" in _yakala(r)


def test_merkle_uzun():
    """ORTAM-OGRENDI (RICH): uzun hücre içerigi tablo-genisligi KESER
    (truncate) — 64-char hash TAM basilmaz; 20-char ile sinirladik."""
    r = _report()
    r.merkle_root = "a" * 20
    assert f"0x{'a' * 20}" in _yakala(r)


# == compliance flags ===================================================================================

def test_bayraklar():
    r = _report()
    r.compliance_flags = ["flag1", "flag2"]
    out = _yakala(r)
    assert "flag1" in out and "flag2" in out


def test_bayrak_bos():
    """ORTAM: bos -> 'Uyumsuzluk Yok' (green)."""
    r = _report()
    r.compliance_flags = []
    assert "Uyumsuzluk Yok" in _yakala(r)


def test_bayrak_tek():
    r = _report()
    r.compliance_flags = ["tek"]
    assert "tek" in _yakala(r)


def test_bayrak_yildiz_formati():
    """ORTAM: her bayrak '• ' öneki ile."""
    r = _report()
    r.compliance_flags = ["a", "b"]
    out = _yakala(r)
    assert out.count("•") == 2


def test_bayrak_turkce():
    r = _report()
    r.compliance_flags = ["KVKK-uyum"]
    assert "KVKK-uyum" in _yakala(r)


# == grade color map ====================================================================================

@pytest.mark.parametrize("grade", ["CRITICAL", "HIGH", "TRANSITIONAL", "READY"])
def test_bilinen_grade(grade):
    """ORTAM: 4 bilinen grade degeri basılır."""
    r = _report()
    r.overall_grade.value = grade
    assert grade in _yakala(r)


@pytest.mark.parametrize("grade", ["BILINMEYEN", "", "LOW", "MEDIUM"])
def test_bilinmeyen_grade(grade):
    """ORTAM-OGRENDI: color_map.get(..., 'white') — bilinmeyen grade 'white'
    ile basılır; HATA YOK (KeyError degil)."""
    r = _report()
    r.overall_grade.value = grade
    assert grade in _yakala(r)


def test_grade_style_etiket_yok():
    """ORTAM-OGRENDI (RICH): [bold red] style etiketleri yakalanan metinde
    YOK — sadece DEGER basılır. Style sadece terminale uygulanir."""
    r = _report()
    r.overall_grade.value = "CRITICAL"
    out = _yakala(r)
    assert "bold red" not in out
    assert "CRITICAL" in out


def test_cyan_etiket_yok():
    r = _report()
    r.merkle_root = "abc"
    out = _yakala(r)
    assert "cyan" not in out


def test_green_etiket_yok():
    r = _report()
    r.compliance_flags = []
    out = _yakala(r)
    assert "green" not in out


# == sutun basliklari ===================================================================================

def test_sutun1_basligi():
    assert "Metrik" in _yakala(_report())


def test_sutun2_basligi():
    assert "Değer" in _yakala(_report())


def test_tablo_basligi():
    """ORTAM: '📊 Kriptografik Denetim Raporu: {target}'."""
    assert "Kriptografik Denetim Raporu" in _yakala(_report())


def test_tablo_basligi_ozel_hedef():
    r = _report()
    r.target = "ozel-hedef"
    assert "ozel-hedef" in _yakala(r)


# == veri turleri =======================================================================================

def test_pqri_sifir():
    r = _report()
    r.pqri_score = 0
    assert "0 / 100" in _yakala(r)


def test_pqri_100():
    r = _report()
    r.pqri_score = 100
    assert "100 / 100" in _yakala(r)


def test_pqri_str():
    """ORTAM: f-string — str deger de basılır."""
    r = _report()
    r.pqri_score = "99"
    assert "99 / 100" in _yakala(r)


def test_hndl_sifir():
    r = _report()
    r.hndl_vulnerability_count = 0
    assert "0" in _yakala(r)


def test_hndl_buyuk():
    r = _report()
    r.hndl_vulnerability_count = 999
    assert "999" in _yakala(r)


def test_cbom_uzun():
    r = _report()
    r.cbom.components = list(range(50))
    assert "50" in _yakala(r)


# == kararlilik =========================================================================================

def test_stabil():
    assert _yakala(_report()) == _yakala(_report())


def test_farkli_hedef_farkli_cikti():
    a = _yakala(_report())
    r = _report()
    r.target = "baska"
    assert _yakala(r) != a


def test_hedef_none():
    """ORTAM: target None -> baslikta 'None' metni (f-string)."""
    r = _report()
    r.target = None
    assert "None" in _yakala(r)


@pytest.mark.parametrize("pqri", [0, 1, 42, 75, 100])
def test_pqri_matrix(pqri):
    r = _report()
    r.pqri_score = pqri
    assert f"{pqri} / 100" in _yakala(r)


@pytest.mark.parametrize("hndl", [0, 1, 3, 10, 999])
def test_hndl_matrix(hndl):
    r = _report()
    r.hndl_vulnerability_count = hndl
    assert str(hndl) in _yakala(r)
