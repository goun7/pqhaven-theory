r"""80-PQHaven mesh_anchor.es_number/_enc_string/_encode/canonicalize/compute_record_hash dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (saf fonksiyonlar; network/DB YASAK).

ORTAM-ANATOMI:
- es_number(x): ECMAScript Number.prototype.toString (RFC 8785 §3.2.2.2);
  NaN/Inf -> ValueError; 0/-0.0 -> '0'; Decimal(repr) trailing-zero
  trimming; k<=n<=21 plain; 0<n<=21 dotted; -6<n<=0 '0.00..s'; else usslu
- _enc_string(s): 7-entry _ESCAPE table (<"\<\b\f\n\r\t>), control
  <0x20 -> \uXXXX, else RAW UTF-8 (non-ASCII kacislanmaz)
- _encode(o, out): None->null; o is True/False->true/false; int
  [-(2^53),2^53] disi -> ValueError; float->es_number; str->_enc_string;
  dict -> UTF-16-BE sorted (RFC 8785 §3.2.3); list/tuple; else TypeError
- canonicalize(obj): _encode list join
- compute_record_hash(prev, rec): sha256(prev + canonicalize(rec 'h' haric))
"""
import hashlib
import math
import sys

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from pqhaven.mesh_anchor import (  # noqa: E402
    _encode, _enc_string, canonicalize, compute_record_hash, es_number,
)


# == es_number =========================================================================================

def test_es_tam():
    """ORTAM: 1.0 -> '1' (ECMAScript tamsayi)."""
    assert es_number(1.0) == "1"


def test_es_sifir():
    """ORTAM: 0 -> '0'."""
    assert es_number(0.0) == "0"


def test_es_negatif_sifir():
    """ORTAM-OGRENDI: -0.0 -> '0' (ECMAScript Number::toString(-0)='0';
  ajan-borsasi _js_sayi ile AYNI; I-JSON)."""
    assert es_number(-0.0) == "0"


def test_es_ondalik():
    assert es_number(1350.5) == "1350.5"
    assert es_number(0.1) == "0.1"


def test_es_kucuk_ussu():
    """ORTAM: 2.93e-07 -> '2.93e-7' (trailing-zero trim + us)."""
    assert es_number(2.93e-07) == "2.93e-7"


def test_es_1e_7():
    assert es_number(1e-07) == "1e-7"


def test_es_1e_6():
    """ORTAM-OGRENDI: 1e-06 -> '0.000001' (n=-6 SINIRDA -6<n<=0 DALINA
    GIRER — '0.000001' usslu DEGIL!)."""
    assert es_number(1e-06) == "0.000001"


def test_es_1e_7_sinir():
    """ORTAM: 1e-7 n=-7 -> -6<n<=0 DISINDA -> uslu '1e-7'."""
    assert es_number(1e-07) == "1e-7"


def test_es_1e21():
    """ORTAM: 1e21 -> '1e+21' (k<=n<=21 n=22'de; n=22>21 -> usslu)."""
    assert es_number(1e21) == "1e+21"


def test_es_buyuk():
    assert es_number(2.5e30) == "2.5e+30"


def test_es_negatif():
    assert es_number(-1350.5) == "-1350.5"
    assert es_number(-2.93e-07) == "-2.93e-7"


def test_es_100():
    """ORTAM: 100.0 -> '100' (k<=n<=21 plain: s+'0'*(n-k))."""
    assert es_number(100.0) == "100"


def test_es_nan():
    """ORTAM-OGRENDI: NaN -> ValueError ('ijson_number_not_finite';
  I-JSON RFC 7493 — ajan-borsasi 'null' / Veridrome ValueError ile
  FARKLI: burada RED)."""
    with pytest.raises(ValueError):
        es_number(float("nan"))


def test_es_inf():
    with pytest.raises(ValueError):
        es_number(float("inf"))
    with pytest.raises(ValueError):
        es_number(float("-inf"))


def test_es_int_girisi():
    """ORTAM: int giris — Decimal(repr(int)) calisir."""
    assert es_number(42) == "42"


def test_es_trailing_zero():
    """ORTAM: 1.50 -> '1.5' (trailing-zero trimming while loop)."""
    assert es_number(1.50) == "1.5"
    assert es_number(100.0) == "100"


def test_es_0_0001():
    """ORTAM: n=-4 -> '0.0001'."""
    assert es_number(0.0001) == "0.0001"


def test_es_donut_tipi():
    assert isinstance(es_number(1.5), str)


def test_es_stabil():
    assert es_number(2.93e-07) == es_number(2.93e-07)


@pytest.mark.parametrize("x,b", [
    (0.0, "0"), (-0.0, "0"), (1.0, "1"), (100.0, "100"), (0.1, "0.1"),
    (2.93e-07, "2.93e-7"), (1e-06, "0.000001"), (1e21, "1e+21"),
    (2.5e30, "2.5e+30"),
])
def test_es_matrix(x, b):
    assert es_number(x) == b


# == _enc_string =======================================================================================

def test_enc_bos():
    assert _enc_string("") == '""'


def test_enc_duz():
    assert _enc_string("merhaba") == '"merhaba"'


def test_enc_tablo_7():
    r"""ORTAM-OGRENDI: _ESCAPE 7-entry — " \ b f n r t (tab/backspace/
  formfeed KISA isimler, \uXXXX DEGIL — kontrol-dalindan ONCE tablo dali)."""
    assert _enc_string('"') == r'"\""'
    assert _enc_string("\\") == r'"\\"'
    assert _enc_string("\b") == r'"\b"'
    assert _enc_string("\f") == r'"\f"'
    assert _enc_string("\n") == r'"\n"'
    assert _enc_string("\r") == r'"\r"'
    assert _enc_string("\t") == r'"\t"'


def test_enc_kontrol():
    """ORTAM: ord<0x20 (tablo disi) -> \\uXXXX."""
    assert _enc_string("\x01") == r'"\u0001"'
    assert _enc_string("\x1f") == r'"\u001f"'


def test_enc_tab_ayni():
    """ORTAM-OGRENDI: tab (0x09) tabloda -> '\\t' ('\\u0009' DEGIL)."""
    assert _enc_string("\t") != r'"\u0009"'
    assert _enc_string("\t") == r'"\t"'


def test_enc_raw_utf8():
    """ORTAM-OGRENDI: non-ASCII RAW (kacislanmaz — ensure_ascii=False)."""
    assert _enc_string("Örnek") == '"Örnek"'
    assert _enc_string("😀") == '"😀"'


def test_enc_solidus_kacis_yok():
    """ORTAM: '/' escape EDILMEZ (JSON'da zorunlu degil)."""
    assert _enc_string("a/b") == '"a/b"'
    assert _enc_string("/x/") == '"/x/"'


def test_enc_donut_tipi():
    assert isinstance(_enc_string("x"), str)


def test_enc_stabil():
    assert _enc_string('a"b') == _enc_string('a"b')


# == _encode / canonicalize ============================================================================

def test_canon_none():
    assert canonicalize(None) == "null"


def test_canon_true():
    assert canonicalize(True) == "true"


def test_canon_false():
    assert canonicalize(False) == "false"


def test_canon_bool_once():
    """ORTAM-OGRENDI: 'o is True'/'o is False' ÖNCE — 'elif isinstance(o,
  bool)' dalı ÖLÜ KOD (bool int'in atası; is ile True/False zaten
  yakalanir). Her halikarda 'true'/'false'."""
    assert canonicalize(True) == "true"
    assert canonicalize(False) == "false"


def test_canon_int():
    assert canonicalize(42) == "42"
    assert canonicalize(0) == "0"
    assert canonicalize(-7) == "-7"


def test_canon_int_2_53():
    """ORTAM: [-(2^53), 2^53] siniri DAHIL."""
    assert canonicalize(2 ** 53) == str(2 ** 53)
    assert canonicalize(-(2 ** 53)) == str(-(2 ** 53))


def test_canon_int_asma():
    """ORTAM-OGRENDI: 2^53+1 -> ValueError ('ijson_number_out_of_range';
  I-JSON RFC 7493 — degeri string olarak serilestir)."""
    with pytest.raises(ValueError):
        canonicalize(2 ** 53 + 1)
    with pytest.raises(ValueError):
        canonicalize(-(2 ** 53) - 1)


def test_canon_float():
    assert canonicalize(1.0) == "1"
    assert canonicalize(2.93e-07) == "2.93e-7"


def test_canon_float_nan():
    """ORTAM: float NaN -> ValueError (es_number)."""
    with pytest.raises(ValueError):
        canonicalize(float("nan"))


def test_canon_str():
    assert canonicalize("merhaba") == '"merhaba"'


def test_canon_str_kacis():
    assert canonicalize('a"b') == r'"a\"b"'


def test_canon_bos_liste():
    assert canonicalize([]) == "[]"


def test_canon_liste():
    assert canonicalize([1, 2, 3]) == "[1,2,3]"


def test_canon_liste_karisik():
    assert canonicalize([1, "a", True, None, False]) == '[1,"a",true,null,false]'


def test_canon_icice_liste():
    assert canonicalize([[1], [2]]) == "[[1],[2]]"


def test_canon_tuple():
    """ORTAM: tuple list dalinda (list|tuple)."""
    assert canonicalize((1, 2)) == "[1,2]"


def test_canon_bos_dict():
    assert canonicalize({}) == "{}"


def test_canon_dict():
    assert canonicalize({"a": 1}) == '{"a":1}'


def test_canon_dict_sorted():
    """ORTAM: ASCII sort — 'b' < 'a' DEGIL; sorted."""
    assert canonicalize({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_canon_dict_utf16_be():
    """ORTAM-OGRENDI (KRITIK): UTF-16-BE code-unit sirasi (RFC 8785
  §3.2.3) — 'Z'(0x5A) < 'a'(0x61) < 'é'(0xE9) (ASCII sort 'Z'>'a'!)."""
    v = canonicalize({"é": 1, "Z": 2, "a": 3})
    assert v == '{"Z":2,"a":3,"é":1}'


def test_canon_dict_utf16_bmp_disi():
    """ORTAM-OGRENDI: BMP-disi '𝓐' (U+1D4D0) -> UTF-16 surrogate pair
  (0xD835 0xDD50) — 'z'(0x7A)'den SONRA (surrogate > BMP)."""
    v = canonicalize({"z": 1, "𝓐": 2})
    assert v.startswith('{"z":1,"𝓐"')


def test_canon_dict_icice():
    assert canonicalize({"a": {"b": 1}}) == '{"a":{"b":1}}'


def test_canon_dict_str_olmayan_anahtar():
    """ORTAM: anahtar str(k) — int -> string."""
    assert canonicalize({1: "x"}) == '{"1":"x"}'


def test_canon_bilinmeyen_tip():
    """ORTAM: else -> TypeError ('unsupported canonical value')."""
    with pytest.raises(TypeError):
        canonicalize({1, 2})
    with pytest.raises(TypeError):
        canonicalize(complex(1, 2))


def test_canon_encode_yan_etki():
    """ORTAM: _encode out listesine APPEND eder, None doner."""
    out = []
    assert _encode(1, out) is None
    assert out == ["1"]


def test_canon_donut_tipi():
    assert isinstance(canonicalize(1), str)


def test_canon_stabil():
    assert canonicalize({"b": 2, "a": 1}) == canonicalize({"b": 2, "a": 1})


@pytest.mark.parametrize("o,b", [
    (None, "null"), (True, "true"), (False, "false"), (42, "42"),
    (1.0, "1"), ("a", '"a"'), ([], "[]"), ({}, "{}"), ([1, "a"], '[1,"a"]'),
])
def test_canon_matrix(o, b):
    assert canonicalize(o) == b


# == compute_record_hash ===============================================================================

def test_hash_basit():
    """ORTAM: sha256(prev + canonicalize(rec 'h' HARIC))."""
    rec = {"a": 1}
    assert compute_record_hash("p", rec) == hashlib.sha256(
        ('p' + canonicalize(rec)).encode("utf-8")).hexdigest()


def test_hash_h_disinda():
    """ORTAM: 'h' alanı HASH-GIRDI DISI (canonicalize'dan cikarilir)."""
    a = compute_record_hash("p", {"a": 1, "h": "x"})
    b = compute_record_hash("p", {"a": 1})
    assert a == b


def test_hash_diger_alan_dahil():
    """ORTAM: 'h' disindaki tum alanlar dahil."""
    assert compute_record_hash("p", {"a": 1, "b": 2}) == hashlib.sha256(
        ('p' + canonicalize({"a": 1, "b": 2})).encode("utf-8")).hexdigest()


def test_hash_prev_dahil():
    """ORTAM: prev hash girdisinin BASINDA."""
    assert compute_record_hash("p1", {"a": 1}) != compute_record_hash("p2", {"a": 1})


def test_hash_bos_rec():
    assert compute_record_hash("p", {}) == hashlib.sha256(
        b"p" + b"{}").hexdigest()


def test_hash_bos_prev():
    assert compute_record_hash("", {"a": 1}) == hashlib.sha256(
        ('{"a":1}').encode("utf-8")).hexdigest()


def test_hash_deterministik():
    assert compute_record_hash("p", {"a": 1}) == compute_record_hash("p", {"a": 1})


def test_hash_uzunluk():
    assert len(compute_record_hash("p", {"a": 1})) == 64


def test_hash_hex():
    """ORTAM: hexdigest — '0x' on-ek YOK."""
    v = compute_record_hash("p", {"a": 1})
    assert all(c in "0123456789abcdef" for c in v)
    assert not v.startswith("0x")


def test_hash_stabil():
    assert compute_record_hash("p", {"a": 1, "b": [1, 2]}) == \
        compute_record_hash("p", {"a": 1, "b": [1, 2]})


def test_hash_sirali():
    """ORTAM: dict anahtar SIRASI hash'i DEGISTIRMEZ (JCS sorted)."""
    assert compute_record_hash("p", {"b": 2, "a": 1}) == \
        compute_record_hash("p", {"a": 1, "b": 2})


# == karakterizasyon ===================================================================================

def test_es_number_amaci():
    """ORTAM-OGRENDI (DOCSTACK): ECMAScript Number.prototype.toString
    (RFC 8785 §3.2.2.2) — tamga_canon.es_number ile bire-bit; NaN/Inf
    RED (I-JSON RFC 7493; ajan-borsasi JSON.stringify 'null' FARKI);
    1e-06 -> '0.000001' (-6<n<=0 dali); 1e-7 -> '1e-7' (sinir disi);
    1e21 -> '1e+21' (n>21 dali); -0.0 -> '0'."""
    assert es_number(1e-06) == "0.000001"
    assert es_number(1e-07) == "1e-7"
    with pytest.raises(ValueError):
        es_number(float("nan"))


def test_canon_amaci():
    """ORTAM-OGRENDI (DOCSTACK): RFC 8785 JCS — 'sorted(o, key=str(k)
    .encode('utf-16-be'))' (§3.2.3) jcs(sort_keys=True)'ten FARKLI:
    BMP-disi karakterler UTF-16 surrogate pair ile ayrilir; bool icin
    'o is True/False' ÖNCE (elif isinstance bool ÖLÜ KOD); int [−2^53,
    2^53] disi ValueError (RFC 7493 I-JSON); else TypeError."""
    assert canonicalize({"é": 1, "Z": 2, "a": 3}) == '{"Z":2,"a":3,"é":1}'
    with pytest.raises(ValueError):
        canonicalize(2 ** 53 + 1)


def test_hash_amaci():
    """ORTAM-OGRENDI (DOCSTACK): Tamga zincir kurali h = sha256(prev +
    jcs(rec 'h' haric)) — 'h' hem hash girdisinde hem de kayit alaninda
    (Veridrome tamga_anchor / Fractiona kanit_meshi ile AYNI zincir
    semasi); '0x' on-ek YOK (hexdigest)."""
    assert compute_record_hash("p", {"a": 1, "h": "x"}) == \
        compute_record_hash("p", {"a": 1})
    assert compute_record_hash("p", {"b": 2, "a": 1}) == \
        compute_record_hash("p", {"a": 1, "b": 2})


def test_enc_amaci():
    """ORTAM-OGRENDI: _ESCAPE 7-entry tablo ('"\\b\\f\\n\\r\\t') — tablo
    dali kontrol dalindan ÖNCE (tab 0x09 '\\t' '\\u0009' DEGIL); ord<0x20
    '\\uXXXX'; non-ASCII RAW UTF-8 (kacislanmaz)."""
    assert _enc_string("\t") == r'"\t"'
    assert _enc_string("\x01") == r'"\u0001"'
    assert _enc_string("Ö") == '"Ö"'
