r"""PQHaven pqhaven.cli._export_csv dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory + tmp_path + FAKE report nesneleri ( dis-dosya/
dis-ag/gercek-CBOM CAGRILMAZ; sadece yazilan CSV dogrulanir).

ORTAM-ANATOMI:
- _export_csv(report, path): CBOM raporunu CSV'ye yazar ( sabit-baslik +
  her-bilesen icin tirnakli-alan satiri)
"""
import csv
import sys

import pytest

sys.path.insert(0, "src")
from pqhaven.cli import _export_csv  # noqa: E402


class FakeAssetType:
    def __init__(self, value):
        self.value = value


class FakeProps:
    def __init__(self, **kw):
        self.asset_type = FakeAssetType(kw.get("asset_type", "data-in-transit"))
        self.algorithm_name = kw.get("algorithm_name", "RSA")
        self.key_size = kw.get("key_size", 2048)
        self.nist_quantum_level = kw.get("nist_quantum_level", 1)
        self.shor_vulnerable = kw.get("shor_vulnerable", True)
        self.recommended_replacement = kw.get(
            "recommended_replacement", "ML-KEM-768")


class FakeComponent:
    def __init__(self, name, **kw):
        self.name = name
        self.crypto_properties = FakeProps(**kw)


class FakeCBOM:
    def __init__(self, components):
        self.components = components


class FakeReport:
    def __init__(self, components):
        self.cbom = FakeCBOM(components)


BASLIK = ("Name,Type,Algorithm,KeySize,NistLevel,ShorVulnerable,"
          "RecommendedReplacement")


# == temel ============================================================================================

def test_csv_baslik(tmp_path):
    """ORTAM: sabit-baslik her-zaman yazilir."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([]), p)
    lines = p.read_text().splitlines()
    assert lines[0] == BASLIK


def test_csv_bos_rapor_sadece_baslik(tmp_path):
    """ORTAM: bilesen-YOK -> yalnizca baslik."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([]), p)
    assert p.read_text().splitlines() == [BASLIK]


def test_csv_tek_bilesen(tmp_path):
    """ORTAM: 1-bilesen -> baslik + 1-satir."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("test")]), p)
    lines = p.read_text().splitlines()
    assert len(lines) == 2


def test_csv_satir_formati(tmp_path):
    """ORTAM: '"isim","tip","algo",key,nist,shor,"oneri"'."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("test")]), p)
    row = p.read_text().splitlines()[1]
    assert row == '"test","data-in-transit","RSA",2048,1,True,"ML-KEM-768"'


def test_csv_satir_csv_parse(tmp_path):
    """ORTAM: csv-modulu ile parse ( 7-alan)."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("test")]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[0] == BASLIK.split(",")
    assert rows[1] == ["test", "data-in-transit", "RSA", "2048", "1",
                       "True", "ML-KEM-768"]


def test_csv_alan_sayisi(tmp_path):
    """ORTAM: her-satir 7-alan ( baslik ile ayni)."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("a"), FakeComponent("b")]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert all(len(r) == 7 for r in rows)


# == tirnaklama =======================================================================================

def test_csv_tirnakli_alanlar(tmp_path):
    """ORTAM-OGRENDI: name/type/algorithm/replacement TIRNAKLI; KeySize/
    NistLevel/ShorVulnerable TIRNAKSIZ ( sayi/bool)."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("x")]), p)
    row = p.read_text().splitlines()[1]
    assert row.startswith('"x","')
    assert row.endswith('"ML-KEM-768"')
    assert '"2048"' not in row


def test_csv_icerdeki_virgul(tmp_path):
    """ORTAM-OGRENDI: alan-icinde virgul TIRNAK icinde guvenli (
    csv.reader ile dogru-parse)."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("a, b")]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[1][0] == "a, b"


def test_csv_icerdeki_tirnak(tmp_path):
    """ORTAM-OGRENDI (GUVENLIK-ONEMLI): alan-icinde tirnak KACISLANMAZ (
    csv.writer DEGIL, raw f-string!) — bu yuzden 'a"b' ham olarak YAZILIR
    ANMA csv.reader ile parse bozulur ( alandaki tırnak alan-ayrimini
    kirar: 'a"b' -> 'ab"' + fazladan-parca); CSV-import eden sistemlerde
    VERI-BOZULMASI riski."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent('a"b')]), p)
    raw = p.read_text().splitlines()[1]
    assert 'a"b' in raw  # ham-metinde korundu
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[1][0] != 'a"b'  # ama parse edilemez ( korrupt)


def test_csv_icerdeki_virgul_oneride(tmp_path):
    """ORTAM: replacement-alaninda virgul."""
    p = tmp_PATH = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent(
        "x", recommended_replacement="ML-KEM-768, fallback")]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[1][6] == "ML-KEM-768, fallback"


def test_csv_turkce_karakter(tmp_path):
    """ORTAM: UTF-8 encoding ( Türkce bilesen-adi)."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("şifreleme-ç")]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[1][0] == "şifreleme-ç"


# == deger cesitliligi ================================================================================

@pytest.mark.parametrize("ks,bek", [(128, "128"), (256, "256"), (2048, "2048"),
                                    (3072, "3072"), (0, "0")])
def test_csv_key_size(tmp_path, ks, bek):
    """ORTAM: key_size tirnaksiz-sayi."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("c", key_size=ks)]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[1][3] == bek


@pytest.mark.parametrize("nist,bek", [(1, "1"), (2, "2"), (3, "3"),
                                      (4, "4"), (5, "5")])
def test_csv_nist_level(tmp_path, nist, bek):
    """ORTAM: nist_quantum_level tirnaksiz-sayi."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("c", nist_quantum_level=nist)]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[1][4] == bek


@pytest.mark.parametrize("shor,bek", [(True, "True"), (False, "False")])
def test_csv_shor_vulnerable(tmp_path, shor, bek):
    """ORTAM-OGRENDI: shor_vulnerable Python-bool str()'e doner (
    'True'/'False' — buyuk-harf; 'true' DEGIL)."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("c", shor_vulnerable=shor)]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[1][5] == bek


@pytest.mark.parametrize("tip", ["data-in-transit", "data-at-rest",
                                 "authentication", "key-establishment"])
def test_csv_asset_type(tmp_path, tip):
    """ORTAM: asset_type .value ( enum-degeri)."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("c", asset_type=tip)]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[1][1] == tip


def test_csv_algoritma_adi(tmp_path):
    """ORTAM: algorithm_name tirnakli."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("c", algorithm_name="ECDSA-P256")]),
                p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[1][2] == "ECDSA-P256"


def test_csv_oneri_bos(tmp_path):
    """ORTAM: bos-recommended_replacement -> '""'."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("c", recommended_replacement="")]),
                p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert rows[1][6] == ""


# == coklu bilesen ====================================================================================

def test_csv_uc_bilesen(tmp_path):
    """ORTAM: 3-bilesen -> baslik + 3-satir."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent(f"c{i}") for i in range(3)]), p)
    assert len(p.read_text().splitlines()) == 4


def test_csv_bilesen_sirasi_korunur(tmp_path):
    """ORTAM: bilesen-sirasi KORUNUR ( list Siralamasi)."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("z"), FakeComponent("a"),
                            FakeComponent("m")]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert [r[0] for r in rows[1:]] == ["z", "a", "m"]


def test_csv_bilesen_benzersiz(tmp_path):
    """ORTAM: ayni-isimli bilesenler ayri-satir."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([FakeComponent("c"), FakeComponent("c")]), p)
    rows = list(csv.reader(p.open(encoding="utf-8")))
    assert len(rows) == 3
    assert rows[1][0] == rows[2][0] == "c"


# == dosya-io =========================================================================================

def test_csv_crlf(tmp_path):
    """ORTAM-OGRENDI: text-mod yazim newline=None -> os.linesep ( Linux'ta
    '\n'; Windows'ta '\r\n' — PLATFORM-BAGIMLI; read_text() ile
    gorunmez, read_bytes() ile dogrulanir)."""
    import os
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([]), p)
    data = p.read_bytes()
    assert data.endswith(b"\n")
    assert data.endswith(os.linesep.encode())


def test_csv_encoding_utf8(tmp_path):
    """ORTAM: encoding='utf-8' ( BOM YOK)."""
    p = tmp_path / "out.csv"
    _export_csv(FakeReport([]), p)
    assert not p.read_bytes().startswith(b"\xef\xbb\xbf")


def test_csv_overwrite(tmp_path):
    """ORTAM: 'w' modu ( varolan-dosya USTUNE-yazar)."""
    p = tmp_path / "out.csv"
    p.write_text("eski-icerik")
    _export_csv(FakeReport([]), p)
    assert p.read_text().splitlines() == [BASLIK]


def test_csv_donut_none(tmp_path):
    """ORTAM: None doner ( deger DEGIL)."""
    p = tmp_path / "out.csv"
    assert _export_csv(FakeReport([]), p) is None


def test_csv_dosya_olusur(tmp_path):
    """ORTAM: dosya yaratilir."""
    p = tmp_path / "yeni" / "alt" / "out.csv"
    p.parent.mkdir(parents=True)
    _export_csv(FakeReport([]), p)
    assert p.exists()


def test_csv_stabil(tmp_path):
    """ORTAM: ayni-rapor ayni-cikti ( deterministik)."""
    p1 = tmp_path / "a.csv"
    p2 = tmp_path / "b.csv"
    r = FakeReport([FakeComponent("c")])
    _export_csv(r, p1)
    _export_csv(r, p2)
    assert p1.read_bytes() == p2.read_bytes()


# == karakterizasyon ===================================================================================

def test_csv_amaci():
    r"""ORTAM-OGRENDI (DOCSTACK): CBOM raporunu CSV'ye yazar ( sabit-7-
alan baslik); name/type/algorithm/replacement TIRNAKLI ( guvenli-alan),
KeySize/NistLevel/ShorVulnerable TIRNAKSIZ ( sayi/bool — ShorVulnerable
'True'/'False' buyuk-harfli Python-bool); bilesen-sirasi KORUNUR; bos-
rapor yalnizca-baslik; UTF-8 ( BOM-yok, Türkce-destek); text-mod
yazim '\n' -> '\r\n'."""
    assert BASLIK == ("Name,Type,Algorithm,KeySize,NistLevel,ShorVulnerable,"
                      "RecommendedReplacement")
