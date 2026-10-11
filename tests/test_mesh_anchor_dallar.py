"""PQHaven mesh_anchor dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (saf fonksiyon + tmp_path — network/DB/subprocess YASAK).

AKADEMIK DAYANAK: ARASTIRMA_AKADEMIK_2026-10-11.md Bolum 5 (RFC 8785)
- es_number: ECMAScript Number.prototype.toString (I-JSON)
- canonicalize: safe-int 2^53, UTF-16 code-unit siralama
"""
import sys
import types

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from pqhaven.mesh_anchor import (  # noqa: E402
    es_number, _enc_string, canonicalize, compute_record_hash,
    build_anchor_record, verify_chain, anchor_report, GENESIS_PREV, ANCHOR_OP,
)


def _mk(target="x", grade="A", score=1.0, comps=None, hndl=0, flags=None,
        root=None):
    """AssessmentReport stub (SimpleNamespace — pydantic modelini yansitir)."""
    return types.SimpleNamespace(
        target=target, pqri_score=score, overall_grade=grade,
        cbom=types.SimpleNamespace(components=comps if comps is not None else []),
        hndl_vulnerability_count=hndl,
        compliance_flags=flags if flags is not None else [],
        merkle_root=root,
    )


# == es_number: ECMAScript Number.prototype.toString ================================================

def test_es_tamsayi():
    assert es_number(42) == "42"


def test_es_ondalik():
    assert es_number(1.5) == "1.5"


def test_es_bir_nokta_sifir():
    """ORTAM: 1.0 -> '1' (ECMAScript trailing-nokta YOK)."""
    assert es_number(1.0) == "1"


def test_es_sifir():
    """ORTAM: 0.0 -> '0'."""
    assert es_number(0.0) == "0"


def test_es_eksi_sifir():
    """ORTAM-OGRENDI: -0.0 -> '0' (negatif-sifir YOK)."""
    assert es_number(-0.0) == "0"


def test_es_negatif():
    assert es_number(-7.5) == "-7.5"


def test_es_kucuk_ustel():
    """ORTAM: 2.93e-07 -> '2.93e-7' (ECMAScript)."""
    assert es_number(2.93e-07) == "2.93e-7"


def test_es_buyuk_ustel():
    """ORTAM: 1e21 -> '1e+21'."""
    assert es_number(1e21) == "1e+21"


def test_es_bir_e_eksi_yedi():
    assert es_number(1e-7) == "1e-7"


def test_es_nan_reject():
    """ORTAM: NaN -> ValueError."""
    with pytest.raises(ValueError, match="not_finite"):
        es_number(float("nan"))


def test_es_inf_reject():
    with pytest.raises(ValueError, match="not_finite"):
        es_number(float("inf"))


def test_es_eksi_inf_reject():
    with pytest.raises(ValueError):
        es_number(float("-inf"))


def test_es_trailing_sifir_temizlenir():
    """ORTAM: 100.0 -> '100' (trailing sifirlar kaydirilir)."""
    assert es_number(100.0) == "100"


def test_es_buyuk_tamsayi():
    assert es_number(1e6) == "1000000"


def test_es_cok_buyuk():
    assert es_number(1e22) == "1e+22"


@pytest.mark.parametrize("x,beklenen", [
    (0.0, "0"), (1.0, "1"), (1.5, "1.5"), (-1.5, "-1.5"),
    (2.93e-07, "2.93e-7"), (1e21, "1e+21"), (1e-7, "1e-7"),
    (42.0, "42"), (100.0, "100"),
])
def test_es_matrix(x, beklenen):
    assert es_number(x) == beklenen


# == _enc_string =======================================================================================

def test_enc_ascii():
    assert _enc_string("abc") == '"abc"'


def test_enc_bos():
    assert _enc_string("") == '""'


def test_enc_tirnak():
    """ORTAM: escape tablosu '\"'."""
    assert _enc_string('a"b') == '"a\\"b"'


def test_enc_backslash():
    assert _enc_string("a\\b") == '"a\\\\b"'


def test_enc_control():
    """ORTAM: < 0x20 -> \\uXXXX."""
    assert _enc_string("a\x00b") == '"a\\u0000b"'


def test_enc_utf8_ham():
    """ORTAM: non-ASCII HAM UTF-8 (escape YOK)."""
    assert _enc_string("é") == '"é"'


def test_enc_astral():
    assert _enc_string("😀") == '"😀"'


def test_enc_turkce():
    assert _enc_string("ğüı") == '"ğüı"'


# == canonicalize ======================================================================================

def test_canon_none():
    assert canonicalize(None) == "null"


def test_canon_true():
    assert canonicalize(True) == "true"


def test_canon_false():
    assert canonicalize(False) == "false"


def test_canon_int():
    assert canonicalize(42) == "42"


def test_canon_safe_int_sinir():
    """ORTAM-OGRENDI: 2^53 KABUL (sinir DAHIL, <=); 2^53+1 -> ValueError."""
    assert canonicalize(2**53) == "9007199254740992"
    with pytest.raises(ValueError, match="out_of_range"):
        canonicalize(2**53 + 1)


def test_canon_safe_int_ustu():
    with pytest.raises(ValueError):
        canonicalize(2**53 + 1)


def test_canon_eksi_sinir():
    """ORTAM-OGRENDI: -2^53 KABUL (sinir DAHIL); -2^53-1 -> ValueError."""
    assert canonicalize(-(2**53)) == "-9007199254740992"
    with pytest.raises(ValueError):
        canonicalize(-(2**53) - 1)


def test_canon_eksi_sinir_ici():
    assert canonicalize(-(2**53) + 1) == "-9007199254740991"


def test_canon_str():
    assert canonicalize("abc") == '"abc"'


def test_canon_float():
    """ORTAM: float -> es_number."""
    assert canonicalize(1.5) == "1.5"


def test_canon_liste():
    assert canonicalize([1, 2]) == "[1,2]"


def test_canon_tuple():
    assert canonicalize((1, 2)) == "[1,2]"


def test_canon_dict_sira():
    """ORTAM: UTF-16 code-unit siralama."""
    assert canonicalize({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_canon_dict_bos():
    assert canonicalize({}) == "{}"


def test_canon_dict_non_str_anahtar():
    """ORTAM: int anahtar -> str'e cevrilir (TypeError DEGIL)."""
    assert canonicalize({1: "a"}) == '{"1":"a"}'


def test_canon_set_reject():
    with pytest.raises(TypeError):
        canonicalize({1, 2})


def test_canon_ic_ice():
    assert canonicalize({"a": {"b": [1]}}) == '{"a":{"b":[1]}}'


def test_canon_karmasik():
    obj = {"z": [1, {"b": 2}], "a": None, "m": True}
    assert canonicalize(obj) == '{"a":null,"m":true,"z":[1,{"b":2}]}'


# == compute_record_hash ===============================================================================

def test_hash_stabil():
    """ORTAM: ayni giris -> ayni hash."""
    h1 = compute_record_hash("p", {"a": 1})
    h2 = compute_record_hash("p", {"a": 1})
    assert h1 == h2


def test_hash_len():
    assert len(compute_record_hash("p", {"a": 1})) == 64


def test_hash_prev_etkili():
    """ORTAM: farkli prev -> farkli hash."""
    assert compute_record_hash("a", {"x": 1}) != compute_record_hash("b", {"x": 1})


def test_hash_record_etkili():
    assert compute_record_hash("p", {"x": 1}) != compute_record_hash("p", {"x": 2})


def test_hash_h_alani_dislanir():
    """ORTAM-OGRENDI: 'h' alani hash girdisine DAHIL DEGIL (kendi-kendini
    besleme YOK) — payload filtrelenir."""
    h1 = compute_record_hash("p", {"a": 1, "h": "xxx"})
    h2 = compute_record_hash("p", {"a": 1})
    assert h1 == h2


def test_hash_str_doner():
    assert isinstance(compute_record_hash("p", {}), str)


# == build_anchor_record ===============================================================================

def test_build_temel():
    rec = build_anchor_record(_mk(), "prev123", ts="2026-01-01T00:00:00Z")
    assert rec["op"] == ANCHOR_OP
    assert rec["target"] == "x"
    assert rec["prev"] == "prev123"
    assert rec["ts"] == "2026-01-01T00:00:00Z"


def test_build_op_sabiti():
    """ORTAM: ANCHOR_OP = 'pqhaven.pq-posture-anchor'."""
    assert ANCHOR_OP == "pqhaven.pq-posture-anchor"


def test_build_genesis_default():
    """ORTAM: prev_hash=None -> GENESIS_PREV."""
    rec = build_anchor_record(_mk(), None, ts="2026-01-01T00:00:00Z")
    assert rec["prev"] == GENESIS_PREV


def test_build_genesis_degeri():
    assert GENESIS_PREV == "00" * 32


def test_build_seq_default():
    """ORTAM: seq=None -> 1."""
    rec = build_anchor_record(_mk(), ts="2026-01-01T00:00:00Z")
    assert rec["seq"] == 1


def test_build_ts_default():
    """ORTAM: ts=None -> now (timezone-utc)."""
    rec = build_anchor_record(_mk())
    assert "T" in rec["ts"]


def test_build_pqri_float():
    rec = build_anchor_record(_mk(score=3.5), ts="t")
    assert rec["pqri_score"] == 3.5
    assert isinstance(rec["pqri_score"], float)


def test_build_grade_str():
    rec = build_anchor_record(_mk(grade="B"), ts="t")
    assert rec["overall_grade"] == "B"


def test_build_grade_enum():
    """ORTAM: grade .value'si varsa onu alir."""
    g = types.SimpleNamespace(value="C")
    rec = build_anchor_record(_mk(grade=g), ts="t")
    assert rec["overall_grade"] == "C"


def test_build_merkle_root_default():
    """ORTAM: merkle_root None -> '00'*32."""
    rec = build_anchor_record(_mk(root=None), ts="t")
    assert rec["cbom_merkle_root"] == "00" * 32


def test_build_merkle_root_varsa():
    rec = build_anchor_record(_mk(root="abc123"), ts="t")
    assert rec["cbom_merkle_root"] == "abc123"


def test_build_cbom_sayi():
    rec = build_anchor_record(_mk(comps=[1, 2, 3]), ts="t")
    assert rec["crypto_asset_count"] == 3


def test_build_cbom_bos():
    rec = build_anchor_record(_mk(comps=[]), ts="t")
    assert rec["crypto_asset_count"] == 0


def test_build_hndl():
    rec = build_anchor_record(_mk(hndl=7), ts="t")
    assert rec["hndl_vulnerability_count"] == 7


def test_build_flags_liste():
    rec = build_anchor_record(_mk(flags=["a", "b"]), ts="t")
    assert rec["compliance_flags"] == ["a", "b"]


def test_build_issuer_yok_default():
    """ORTAM: issuer=None -> 'issuer' alani YOK."""
    rec = build_anchor_record(_mk(), ts="t")
    assert "issuer" not in rec


def test_build_issuer_varsa():
    rec = build_anchor_record(_mk(), ts="t", issuer="goun7")
    assert rec["issuer"] == "goun7"


def test_build_h_alani():
    """ORTAM: 'h' = compute_record_hash(prev, record)."""
    rec = build_anchor_record(_mk(), "p1", ts="t")
    assert rec["h"] == compute_record_hash("p1", rec)


def test_build_h_kendini_dislar():
    """ORTAM: 'h' hesabi sirasinda 'h' alani YOK (ben ekleyemem)."""
    rec = build_anchor_record(_mk(), "p1", ts="t")
    assert "h" in rec
    # tekrar hesapla — ayni
    assert compute_record_hash("p1", rec) == rec["h"]


def test_build_stabil():
    r = build_anchor_record(_mk(), "p1", ts="2026-01-01T00:00:00Z")
    assert r == build_anchor_record(_mk(), "p1", ts="2026-01-01T00:00:00Z")


# == verify_chain ======================================================================================

def test_verify_bos():
    """ORTAM: bos zincir -> (GENESIS, 'ok')."""
    tip, st = verify_chain([])
    assert st == "ok"
    assert tip == GENESIS_PREV


def test_verify_tek_kayit():
    rec = build_anchor_record(_mk(), GENESIS_PREV, seq=1, ts="t")
    tip, st = verify_chain([rec])
    assert st == "ok"
    assert tip == rec["h"]


def test_verify_iki_kayit():
    r1 = build_anchor_record(_mk("a"), GENESIS_PREV, seq=1, ts="t1")
    r2 = build_anchor_record(_mk("b"), r1["h"], seq=2, ts="t2")
    tip, st = verify_chain([r1, r2])
    assert st == "ok"
    assert tip == r2["h"]


def test_verify_prev_kirik():
    """ORTAM: prev uyumsuz -> 'broken@N'."""
    r1 = build_anchor_record(_mk(), GENESIS_PREV, seq=1, ts="t1")
    r2 = build_anchor_record(_mk("b"), "wrong", seq=2, ts="t2")
    tip, st = verify_chain([r1, r2])
    assert st == "broken@2"
    assert tip is None


def test_verify_h_kirik():
    """ORTAM: h uyumsuz -> 'broken@N'."""
    r1 = build_anchor_record(_mk(), GENESIS_PREV, seq=1, ts="t1")
    r2 = build_anchor_record(_mk("b"), r1["h"], seq=2, ts="t2")
    r2["h"] = "wrong"
    tip, st = verify_chain([r1, r2])
    assert st == "broken@2"
    assert tip is None


def test_verify_seq_kirik():
    """ORTAM: seq uyumsuz -> 'broken@N'."""
    r1 = build_anchor_record(_mk(), GENESIS_PREV, seq=1, ts="t1")
    r2 = build_anchor_record(_mk("b"), r1["h"], seq=5, ts="t2")
    tip, st = verify_chain([r1, r2])
    assert st == "broken@2"


def test_verify_ilk_prev_genesis_degil():
    """ORTAM: ilk kayit prev=GENESIS degilse -> broken@1."""
    r1 = build_anchor_record(_mk(), "wrong-prev", seq=1, ts="t1")
    tip, st = verify_chain([r1])
    assert st == "broken@1"


def test_verify_h_kaybi_exception():
    """ORTAM: 'h' alani yok -> Exception -> 'broken@N'."""
    r1 = build_anchor_record(_mk(), GENESIS_PREV, seq=1, ts="t1")
    tip, st = verify_chain([{"prev": GENESIS_PREV, "seq": 1}])
    assert st == "broken@1"
    assert tip is None


def test_verify_kayit_tipi_dict_degil():
    """ORTAM: None kaydi -> Exception -> broken@1."""
    tip, st = verify_chain([None])
    assert st == "broken@1"


def test_verify_generator():
    """ORTAM: generator/iterator kabul eder."""
    r1 = build_anchor_record(_mk(), GENESIS_PREV, seq=1, ts="t1")
    tip, st = verify_chain(r for r in [r1])
    assert st == "ok"


def test_verify_tip_hash_gercek():
    r1 = build_anchor_record(_mk(), GENESIS_PREV, seq=1, ts="t1")
    r2 = build_anchor_record(_mk("b"), r1["h"], seq=2, ts="t2")
    tip, st = verify_chain([r1, r2])
    assert tip == r2["h"]


# == anchor_report ======================================================================================

def test_anchor_dosyaya(tmp_path):
    """ORTAM: ledger.jsonl'e yazar."""
    p = tmp_path / "ledger.jsonl"
    rec = anchor_report(_mk(), p, ts="2026-01-01T00:00:00Z")
    assert rec["target"] == "x"
    assert p.exists()
    line = p.read_text(encoding="utf-8").strip()
    assert '"op"' in line


def test_anchor_h_alani(tmp_path):
    p = tmp_path / "l.jsonl"
    rec = anchor_report(_mk(), p, ts="t")
    assert "h" in rec
    assert len(rec["h"]) == 64


def test_anchor_ekle_kirik_zincir(tmp_path):
    """ORTAM: mevcut zincir kiriksa fail-closed."""
    p = tmp_path / "l.jsonl"
    p.write_text('{"prev":"WRONG","seq":1,"h":"x"}\n', encoding="utf-8")
    with pytest.raises(Exception):
        anchor_report(_mk(), p, ts="t")


def test_anchor_iki_kayit(tmp_path):
    p = tmp_path / "l.jsonl"
    r1 = anchor_report(_mk("a"), p, ts="t1")
    r2 = anchor_report(_mk("b"), p, ts="t2")
    assert r1["target"] == "a"
    assert r2["target"] == "b"
    assert r2["prev"] == r1["h"]


def test_anchor_seq_artar(tmp_path):
    p = tmp_path / "l.jsonl"
    r1 = anchor_report(_mk("a"), p, ts="t1")
    r2 = anchor_report(_mk("b"), p, ts="t2")
    assert r1["seq"] == 1
    assert r2["seq"] == 2


def test_anchor_issuer(tmp_path):
    p = tmp_path / "l.jsonl"
    rec = anchor_report(_mk(), p, issuer="goun7", ts="t")
    assert rec["issuer"] == "goun7"


def test_anchor_issuer_yok(tmp_path):
    p = tmp_path / "l.jsonl"
    rec = anchor_report(_mk(), p, ts="t")
    assert "issuer" not in rec


def test_anchor_zincir_dogrulanabilir(tmp_path):
    """ORTAM: yazilan ledger verify_chain ile dogrulanir."""
    p = tmp_path / "l.jsonl"
    anchor_report(_mk("a"), p, ts="t1")
    anchor_report(_mk("b"), p, ts="t2")
    import json
    recs = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    tip, st = verify_chain(recs)
    assert st == "ok"


def test_anchor_bos_zincir_path(tmp_path):
    """ORTAM: olmayan dosya -> olusturur."""
    p = tmp_path / "new" / "l.jsonl"
    p.parent.mkdir()
    rec = anchor_report(_mk(), p, ts="t")
    assert p.exists()
    assert rec["seq"] == 1


def test_anchor_ts_varsayilan(tmp_path):
    p = tmp_path / "l.jsonl"
    rec = anchor_report(_mk(), p)
    assert "T" in rec["ts"]
