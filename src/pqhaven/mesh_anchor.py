"""PQHaven -> TamgaProtocol mesh anchor bridge (durable PQ-posture evidence).

Mesh konumu
-----------
TAMGA-MESH baglanti matrisinde PQHaven post-quantum katmanidir ve
``05_acik_kaynak/TamgaProtocol`` mesh'in **kalici kanit-anchor** katmanidir.
Bu modul iki katmani birlestirir: PQ tarayicinin urettigi CBOM Merkle kokunu
+ PQRI skorunu, Tamga'nin hash-zincirlenmis ``ledger.jsonl`` kanit modelinde
**bayt-uyumlu** bir kayda donusturur.

Neden degerli?
--------------
Mosca tezine gore "harvest now, decrypt later" tehditi yalnizca verileri
degil, *neyin ne zaman savasmasiz oldugu* kaydini da tehdit eder: kuantum
rakov (veya bugun gizlice girmis bir saldirgan) crypto-borc envanterini
geriye donuk yeniden yazip "zaten PQ-hazirdik" diyebilir. CBOM Merkle kokunu
o anin kanitina sabitleyerek (timestamp + oncelik zinciri) bu geri-yazimi
tespit-edilebilir kilariz. Bu, "PQ tarayici + Merkle koku" deseninin mesh'teki
dogal kapanmasidir.

Uyumluluk (bire-bit)
--------------------
Tamga ``tamga_runner._verify_chain`` zincir kurali::

    h = sha256( prev_str + jcs(rec  # 'h' ve 'node_sig' haric
                              ) ).hexdigest()
    seq 1'den baslar, prev '0'*64 ile baslar, her kaydin prev'i onceki h'dir.

Bu modul ayni kurali ve RFC 8785 (JCS) canonicalization'i icerir; boylece
bir Tamga dogrulayicisi (veya ``tamga_verify_mini.py``) PQHaven kayitlarini
PQHaven'i kurmadan dogrulayabilir. ``tamga_canon`` ile bayt-paritesi
``tests/test_mesh_anchor.py`` icinde makine-ceklinir.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

__all__ = [
    "GENESIS_PREV",
    "ANCHOR_OP",
    "canonicalize",
    "compute_record_hash",
    "build_anchor_record",
    "verify_chain",
    "anchor_report",
]

# Tamga ledger genesis prev'i (tamga_runner._verify_chain ile ayni)
GENESIS_PREV = "0" * 64

# Bu ureticinin kanit turu. Tamga'nin unknown_ops yardimcisi bilinmeyen
# op'lari 'garanti disi' olarak isaretler (uretici-garantisi yalnizca kendi
# emitter'larini kapsar) -- bu davranis bicimi kasitlidir: alici karar verir.
ANCHOR_OP = "pqhaven.pq-posture-anchor"

_ESCAPE = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
    "\n": "\\n", "\r": "\\r", "\t": "\\t",
}


def es_number(x: float) -> str:
    """ECMAScript ``Number.prototype.toString`` (RFC 8785 §3.2.2.2).

    ``tamga_canon.es_number`` ile bire-bit: NaN/Inf reddedilir (I-JSON),
    ``1.0`` -> ``"1"``, ``2.93e-07`` -> ``"2.93e-7"``.
    """
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError(
            "ijson_number_not_finite: NaN/Infinity I-JSON (RFC 7493) kumesinde degil"
        )
    if x == 0:  # -0.0 dahil ECMAScript "0" basar
        return "0"
    neg = x < 0
    digits, exp = Decimal(repr(abs(x))).as_tuple()[-2:]
    while len(digits) > 1 and digits[-1] == 0:
        digits = digits[:-1]
        exp = exp + 1
    k = len(digits)
    n = exp + k
    s = "".join(map(str, digits))
    if k <= n <= 21:
        body = s + "0" * (n - k)
    elif 0 < n <= 21:
        body = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + s
    else:
        e = n - 1
        mant = s if k == 1 else s[0] + "." + s[1:]
        body = mant + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return ("-" if neg else "") + body


def _enc_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESCAPE:
            out.append(_ESCAPE[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)  # raw UTF-8; non-ASCII kacislanmaz
    out.append('"')
    return "".join(out)


def _encode(o: Any, out: List[str]) -> None:
    if o is None:
        out.append("null")
    elif o is True:
        out.append("true")
    elif o is False:
        out.append("false")
    elif isinstance(o, bool):  # bool, int'in alt sinifi
        out.append("true" if o else "false")
    elif isinstance(o, int):
        if not (-(2 ** 53) <= o <= 2 ** 53):
            raise ValueError(
                "ijson_number_out_of_range: [−2^53, 2^53] disinda tamsayi "
                "I-JSON (RFC 7493) kumesinde degil; degeri string olarak serilestirin"
            )
        out.append(str(o))
    elif isinstance(o, float):
        out.append(es_number(o))
    elif isinstance(o, str):
        out.append(_enc_string(o))
    elif isinstance(o, dict):
        out.append("{")
        first = True
        # UTF-16 code-unit sirasi (RFC 8785 §3.2.3) — Python code-point sirasindan
        # BMP-disi karakterler ile ayrilir; jcs(sort_keys=True) YETERLI DEGILDIR.
        for key in sorted(o, key=lambda k: str(k).encode("utf-16-be")):
            if not first:
                out.append(",")
            first = False
            out.append(_enc_string(str(key)))
            out.append(":")
            _encode(o[key], out)
        out.append("}")
    elif isinstance(o, (list, tuple)):
        out.append("[")
        first = True
        for item in o:
            if not first:
                out.append(",")
            first = False
            _encode(item, out)
        out.append("]")
    else:
        raise TypeError(f"unsupported canonical value: {type(o).__name__}")


def canonicalize(obj: Any) -> str:
    """RFC 8785 (JCS) canonical serialization — ``tamga_canon.jcs`` ile bire-bit."""
    out: List[str] = []
    _encode(obj, out)
    return "".join(out)


def compute_record_hash(prev: str, record: Dict[str, Any]) -> str:
    """Tamga zincir kurali: ``h = sha256(prev + jcs(rec 'h' haric))``.

    ``prev`` hem hash girdisinde hem de kayit alaninda bulunur (Tamga ile ayni).
    """
    payload = {k: v for k, v in record.items() if k != "h"}
    digest = hashlib.sha256((prev + canonicalize(payload)).encode("utf-8")).hexdigest()
    return digest


def build_anchor_record(
    report: Any,
    prev_hash: str = GENESIS_PREV,
    seq: Optional[int] = None,
    ts: Optional[str] = None,
    issuer: Optional[str] = None,
) -> Dict[str, Any]:
    """Bir ``AssessmentReport``'u Tamga-uyumlu kalici kanit kaydina donusturur.

    Kayit, Tamga ``ledger.jsonl`` zincirine dogrudan eklenebilir formattadir;
    ``h`` alanı ``verify_chain`` (veya tamga_verify_mini) tarafindan
    bagimsiz olarak yeniden hesaplanabilir.
    """
    if prev_hash is None:
        prev_hash = GENESIS_PREV
    if seq is None:
        seq = 1
    if ts is None:
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    merkle_root = report.merkle_root or "00" * 32
    grade = (
        report.overall_grade.value
        if hasattr(report.overall_grade, "value")
        else str(report.overall_grade)
    )

    record: Dict[str, Any] = {
        "op": ANCHOR_OP,
        "seq": seq,
        "prev": prev_hash,
        "ts": ts,
        "target": report.target,
        "pqri_score": float(report.pqri_score),
        "overall_grade": grade,
        # CBOM'un tumune yapilan commitment — "PQ tarayici + Merkle koku" deseni
        "cbom_merkle_root": merkle_root,
        "hndl_vulnerability_count": int(report.hndl_vulnerability_count),
        "crypto_asset_count": len(report.cbom.components),
        "compliance_flags": list(report.compliance_flags),
    }
    if issuer is not None:
        record["issuer"] = issuer

    record["h"] = compute_record_hash(prev_hash, record)
    return record


def verify_chain(records: Iterable[Dict[str, Any]]) -> Tuple[Optional[str], str]:
    """Tamga zincir dogrulama kuralinin bagimsiz stdlib yeniden implementasyonu.

    Karsi taraf (PQHaven VEYA Tamga kurmadan) kayitlari dogrular —
    ``tamga_verify_mini`` felsefesinde bir tek-gercek paritesi.

    Donus: ``(tip_hash, "ok")`` veya ``(None, "broken@<n>")``.
    """
    prev_h: str = GENESIS_PREV
    n = 0
    try:
        for rec in records:
            n += 1
            expected = compute_record_hash(rec.get("prev", ""), rec)
            if (
                rec.get("prev") != prev_h
                or rec.get("h") != expected
                or rec.get("seq") != n
            ):
                return None, f"broken@{n}"
            prev_h = rec["h"]
    except Exception:
        return None, f"broken@{n}"
    return prev_h, "ok"


def anchor_report(
    report: Any,
    ledger_path: str | Path,
    issuer: Optional[str] = None,
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """``report``'u ``ledger_path``'deki Tamga zincirine uyguna ekler (append).

    Mevcut zinciri once dogrular; kirik ise fail-closed (kayit eklemez).
    Donus: eklenen kayit (``h`` dahil).
    """
    path = Path(ledger_path)
    records: List[Dict[str, Any]] = []
    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        # fail-closed: kirik zincire asla ekleme
        _, reason = verify_chain(records)
        if reason != "ok":
            raise ValueError(f"refusing to anchor onto broken ledger: {reason}")

    seq = len(records) + 1
    prev_hash = records[-1]["h"] if records else GENESIS_PREV

    record = build_anchor_record(
        report, prev_hash=prev_hash, seq=seq, ts=ts, issuer=issuer
    )

    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record
