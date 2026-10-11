"""80-PQHaven cli._render_report_table dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (console MONKEYPATCH — dis cagri YOK).
Rich Table render (kriptografik denetim raporu).
"""
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from pqhaven import cli as CLI  # noqa: E402
from pqhaven.cli import _render_report_table  # noqa: E402
from pqhaven.models import PqcRiskGrade  # noqa: E402
from rich.table import Table  # noqa: E402
from rich.console import Console  # noqa: E402


class Yakala:
    def __init__(self):
        self.tablolar = []

    def print(self, t, *a, **k):
        if isinstance(t, Table):
            self.tablolar.append(t)


class YakTable(Table):
    """add_row argumanlarini kaydeden Table."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._satirlar = []

    def add_row(self, *args, **kw):
        self._satirlar.append(args)
        return super().add_row(*args, **kw)


@pytest.fixture()
def yak(monkeypatch):
    y = Yakala()
    monkeypatch.setattr(CLI, "console", y)
    monkeypatch.setattr(CLI, "Table", YakTable)
    return y


def _r(**kw):
    g = {"overall_grade": PqcRiskGrade.READY, "pqri_score": 42,
         "target": "hedef-1", "hndl_vulnerability_count": 3,
         "cbom": SimpleNamespace(components=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
         "merkle_root": "abcd1234", "compliance_flags": ["flag1"]}
    g.update(kw)
    return SimpleNamespace(**g)


def _tablo(yak):
    assert len(yak.tablolar) == 1
    return yak.tablolar[0]


def _hucre(t, satir, sutun):
    """Kaydedilen ham add_row argumanindan plain-text (rich-tag'ler soyulmus)."""
    from rich.text import Text
    h = t._satirlar[satir][sutun]
    if isinstance(h, str):
        return Text.from_markup(h).plain
    if isinstance(h, Text):
        return h.plain
    return str(h)


# == temel ============================================================================================

def test_table_doner(yak):
    _render_report_table(_r())
    assert isinstance(_tablo(yak), Table)


def test_title(yak):
    """ORTAM: title '📊 Kriptografik Denetim Raporu: {target}'."""
    _render_report_table(_r(target="hedef-x"))
    assert "hedef-x" in _tablo(yak).title


def test_title_emoji(yak):
    _render_report_table(_r())
    assert "📊" in _tablo(yak).title


def test_iki_kolon(yak):
    """ORTAM: 2-kolon."""
    _render_report_table(_r())
    assert len(_tablo(yak).columns) == 2


def test_kolon_basliklari(yak):
    _render_report_table(_r())
    t = _tablo(yak)
    assert t.columns[0].header == "Metrik / Parametre"
    assert t.columns[1].header == "Değer"


def test_alti_satir(yak):
    """ORTAM: 6-satir."""
    _render_report_table(_r())
    assert len(_tablo(yak).rows) == 6


# == satir icerikleri ==================================================================================

def test_pqri_satiri(yak):
    """ORTAM: 'PQRI Risk Skoru' | f'{score} / 100'."""
    _render_report_table(_r(pqri_score=77))
    assert _hucre(_tablo(yak), 0, 0) == "PQRI Risk Skoru"
    assert _hucre(_tablo(yak), 0, 1) == "77 / 100"


def test_derece_satiri(yak):
    _render_report_table(_r(overall_grade=PqcRiskGrade.TRANSITIONAL))
    assert _hucre(_tablo(yak), 1, 0) == "Kuantum Hazırlık Derecesi"
    assert _hucre(_tablo(yak), 1, 1) == "TRANSITIONAL"


def test_hndl_satiri(yak):
    _render_report_table(_r(hndl_vulnerability_count=5))
    assert _hucre(_tablo(yak), 2, 0) == "HNDL Tehditli Varlık"
    assert _hucre(_tablo(yak), 2, 1) == "5"


def test_cbom_sayi_satiri(yak):
    """ORTAM: len(report.cbom.components)."""
    _render_report_table(_r(cbom=SimpleNamespace(components=[1, 2])))
    assert _hucre(_tablo(yak), 3, 0) == "Toplam CBOM Varlığı"
    assert _hucre(_tablo(yak), 3, 1) == "2"


def test_bos_cbom(yak):
    _render_report_table(_r(cbom=SimpleNamespace(components=[])))
    assert _hucre(_tablo(yak), 3, 1) == "0"


def test_merkle_satiri(yak):
    """ORTAM: [cyan]0x{root}[/cyan]."""
    _render_report_table(_r(merkle_root="rootabc"))
    assert "Merkle" in _hucre(_tablo(yak), 4, 0)
    assert "0xrootabc" in _hucre(_tablo(yak), 4, 1)


def test_merkle_yok(yak):
    """ORTAM: merkle_root FALSY -> 'Yok'."""
    _render_report_table(_r(merkle_root=None))
    assert _hucre(_tablo(yak), 4, 1) == "Yok"


def test_merkle_bos_str(yak):
    _render_report_table(_r(merkle_root=""))
    assert _hucre(_tablo(yak), 4, 1) == "Yok"


def test_bayrak_satiri(yak):
    _render_report_table(_r(compliance_flags=["a", "b"]))
    assert _hucre(_tablo(yak), 5, 0) == "Mevzuat Bayrakları"
    v = _hucre(_tablo(yak), 5, 1)
    assert "• a" in v and "• b" in v


def test_bos_flags_uyumsuzluk_yok(yak):
    """ORTAM: bos-flags -> '[green]Uyumsuzluk Yok[/green]'."""
    _render_report_table(_r(compliance_flags=[]))
    assert _hucre(_tablo(yak), 5, 1) == "Uyumsuzluk Yok"


# == color_map =========================================================================================

@pytest.mark.parametrize("grade", ["CRITICAL", "HIGH", "TRANSITIONAL", "READY"])
def test_color_map(yak, grade):
    """ORTAM: 4-grade color-map."""
    _render_report_table(_r(overall_grade=PqcRiskGrade[grade]))
    assert _hucre(_tablo(yak), 1, 1) == grade


# == cesitli ===========================================================================================

def test_cok_flags(yak):
    _render_report_table(_r(compliance_flags=["a", "b", "c"]))
    v = _hucre(_tablo(yak), 5, 1)
    assert v.count("•") == 3


def test_turkce_flag(yak):
    _render_report_table(_r(compliance_flags=["Türkçe-flag"]))
    assert "Türkçe-flag" in _hucre(_tablo(yak), 5, 1)


def test_sifir_pqri(yak):
    _render_report_table(_r(pqri_score=0))
    assert _hucre(_tablo(yak), 0, 1) == "0 / 100"


def test_yuz_pqri(yak):
    _render_report_table(_r(pqri_score=100))
    assert _hucre(_tablo(yak), 0, 1) == "100 / 100"


def test_yuksek_hndl(yak):
    _render_report_table(_r(hndl_vulnerability_count=999))
    assert _hucre(_tablo(yak), 2, 1) == "999"


def test_turkce_target(yak):
    _render_report_table(_r(target="Türkçe-hedef"))
    assert "Türkçe-hedef" in _tablo(yak).title


def test_uzun_merkle(yak):
    root = "x" * 64
    _render_report_table(_r(merkle_root=root))
    assert "0x" + root in _hucre(_tablo(yak), 4, 1)


def test_uzun_flag(yak):
    _render_report_table(_r(compliance_flags=["x" * 200]))
    assert "x" * 200 in _hucre(_tablo(yak), 5, 1)


def test_repeatable(yak):
    _render_report_table(_r())
    a = _hucre(_tablo(yak), 0, 1)
    yak.tablolar.clear()
    _render_report_table(_r())
    b = _hucre(_tablo(yak), 0, 1)
    assert a == b


@pytest.mark.parametrize("n", [0, 1, 2, 5, 10])
def test_flags_matrix(yak, n):
    flags = [f"f{i}" for i in range(n)]
    _render_report_table(_r(compliance_flags=flags))
    assert _hucre(_tablo(yak), 5, 1).count("•") == n


@pytest.mark.parametrize("score", [0, 1, 42, 50, 99, 100])
def test_pqri_matrix(yak, score):
    _render_report_table(_r(pqri_score=score))
    assert _hucre(_tablo(yak), 0, 1) == f"{score} / 100"


@pytest.mark.parametrize("n", [0, 1, 3, 10, 100])
def test_cbom_matrix(yak, n):
    _render_report_table(_r(cbom=SimpleNamespace(components=list(range(n)))))
    assert _hucre(_tablo(yak), 3, 1) == str(n)
