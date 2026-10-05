"""Tests for the PQHaven -> TamgaProtocol mesh anchor bridge.

Uc kanit:
  1. zincir kurma + bagimsiz dogrulama + ledger append
  2. RFC 8785 canonicalization'in tamga_canon ile BAYT-PARITESI (mesh bagi
     iddia degil, makine-cekilir)
  3. degistirme (tamper) tespiti + kirik zincire fail-closed korumasi
"""

import importlib.util
import json
import os
import random
from pathlib import Path

import pytest

from pqhaven.engine import PQScanEngine
from pqhaven.mesh_anchor import (
    ANCHOR_OP,
    GENESIS_PREV,
    anchor_report,
    build_anchor_record,
    canonicalize,
    compute_record_hash,
    verify_chain,
)

TAMGA_ROOT_CANDIDATES = [
    os.environ.get("TAMGA_ROOT"),
    str(Path(__file__).resolve().parents[3] / "05_acik_kaynak" / "TamgaProtocol"),
    "/home/gokun/projects/05_acik_kaynak/TamgaProtocol",
]


def _load_tamga_canon():
    """tamga_canon.py'yi dosya yolundan yukle (sadece parity testi icin)."""
    for root in TAMGA_ROOT_CANDIDATES:
        if not root:
            continue
        cand = Path(root) / "tamga_canon.py"
        if cand.exists():
            spec = importlib.util.spec_from_file_location("tamga_canon", cand)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


def _make_reports():
    engine = PQScanEngine()
    legacy = engine.assess_target(
        "api.test.com",
        [
            {"name": "web-cert", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048},
            {"name": "broken-hash", "algorithm": "MD5", "type": "algorithm", "key_size": 128},
        ],
    )
    ready = engine.assess_target(
        "safe.internal",
        [
            {"name": "web-kex", "algorithm": "ML-KEM-768", "type": "protocol", "key_size": 768},
            {"name": "code-sign", "algorithm": "ML-DSA-65", "type": "algorithm", "key_size": 192},
        ],
        shelf_life_years=2.0,
        migration_time_years=1.0,
        crqc_arrival_years=10.0,
    )
    return legacy, ready


def test_anchor_chain_builds_and_verifies(tmp_path):
    legacy, ready = _make_reports()

    rec1 = build_anchor_record(legacy, ts="2026-10-05T13:00:00+00:00")
    rec2 = build_anchor_record(
        ready, prev_hash=rec1["h"], seq=2, ts="2026-10-05T13:01:00+00:00"
    )

    # Kayit formati: Tamga ledger modeliyle ayni alanlar
    assert rec1["op"] == ANCHOR_OP
    assert rec1["seq"] == 1
    assert rec1["prev"] == GENESIS_PREV
    assert rec2["prev"] == rec1["h"]
    assert len(rec1["h"]) == 64 and rec1["h"] != rec2["h"]
    # PQ kaniti gercekten bagli: Merkle koku + PQRI + HNDL sayisi
    assert rec1["cbom_merkle_root"] == legacy.merkle_root
    assert rec1["pqri_score"] == legacy.pqri_score
    assert rec1["hndl_vulnerability_count"] == legacy.hndl_vulnerability_count
    assert rec1["crypto_asset_count"] == 2
    assert rec1["overall_grade"] == "CRITICAL" or rec1["pqri_score"] > 0

    # Bagimsiz yeniden hesap — h, payload'dan turetiliyor, sabit degil
    recomputed = compute_record_hash(GENESIS_PREV, rec1)
    assert recomputed == rec1["h"]

    # Zincir dogrulama (pqhaven'in kendi verify_chain)
    tip, reason = verify_chain([rec1, rec2])
    assert reason == "ok"
    assert tip == rec2["h"]

    # Bos kayit listesi kirik degil
    assert verify_chain([]) == (GENESIS_PREV, "ok")

    # ledger.jsonl'e append -> dosyadan tekrar dogrula
    ledger = tmp_path / "ledger.jsonl"
    anchor_report(legacy, ledger, ts="2026-10-05T13:00:00+00:00")
    anchor_report(ready, ledger, ts="2026-10-05T13:01:00+00:00")
    with ledger.open("r", encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
    assert len(records) == 2
    tip2, reason2 = verify_chain(records)
    assert reason2 == "ok" and tip2 == records[-1]["h"]


def test_canonicalization_byte_parity_with_tamga_canon():
    tamga_canon = _load_tamga_canon()
    if tamga_canon is None:
        pytest.skip("tamga_canon bulunamadi (TAMGA_ROOT disinda) — parity testi atlandi")

    rng = random.Random(20261005)
    payloads = [
        {
            "op": ANCHOR_OP,
            "seq": 1,
            "prev": GENESIS_PREV,
            "ts": "2026-10-05T13:00:00+00:00",
            "target": "api.test.com",
            "pqri_score": 87.34,
            "overall_grade": "CRITICAL",
            "cbom_merkle_root": "a" * 64,
            "hndl_vulnerability_count": 2,
            "crypto_asset_count": 5,
            "compliance_flags": ["KVKK_MADDE_12_HNDL_VIOLATION_RISK", "NIS2_ARTICLE_21_CRYPTO_POLICY_NON_COMPLIANT"],
        },
        # ECMAScript sayi formatinin ayrildigi durumlar: 1.0 -> "1", bilimsel
        {"x": 1.0, "y": 2.93e-07, "z": 1e16, "w": -0.0, "big": 1234567890123},
        # UTF-16 code-unit sirasi: 'ü' (U+00FC) ile 'z' (U+007A) arasinda emoji
        {"zeta": 1, "üü": 2, "Ωmega": 3, "a𝄞b": 4},
        # Liste + icice dict + null/bool
        {"flags": ["a", "b", "c"], "nested": {"k": None, "j": True, "i": False}},
        # Rastgele agaca benzeyen payload
        {
            "n": [rng.randint(-1000, 1000) for _ in range(20)],
            "f": [round(rng.uniform(-1e6, 1e6), 6) for _ in range(10)],
            "s": ["esc\"ape\\", "tab\tnewline\n", "unicode-çğıöşü"],
        },
    ]

    for payload in payloads:
        expected = tamga_canon.jcs(payload).decode("utf-8")
        assert canonicalize(payload) == expected, (
            f"JCS parity broken for payload keys={sorted(payload)}"
        )

    # Sayi ve string birim testleri (ECMAScript number formati)
    for val in [0.0, -0.0, 1.0, 87.34, 2.93e-07, 1e16, 1e21, 1e-7, 1234567890123]:
        assert canonicalize({"v": val}) == tamga_canon.jcs({"v": val}).decode("utf-8")


def test_chain_tamper_detection_and_fail_closed(tmp_path):
    legacy, ready = _make_reports()
    rec1 = build_anchor_record(legacy, ts="2026-10-05T13:00:00+00:00")
    rec2 = build_anchor_record(
        ready, prev_hash=rec1["h"], seq=2, ts="2026-10-05T13:01:00+00:00"
    )

    # 1. PQRI degistirilirse (geri-yezum saldirisi: "zaten hazirdik")
    tampered_pqri = dict(rec2)
    tampered_pqri["pqri_score"] = 5.0
    assert verify_chain([rec1, tampered_pqri])[1] == "broken@2"

    # 2. Merkle koku degistirilirse
    tampered_root = dict(rec2)
    tampered_root["cbom_merkle_root"] = "f" * 64
    assert verify_chain([rec1, tampered_root])[1] == "broken@2"

    # 3. seq atlarsa
    bad_seq = dict(rec2)
    bad_seq["seq"] = 3
    assert verify_chain([rec1, bad_seq])[1] == "broken@2"

    # 4. h sahte ise
    fake_h = dict(rec2)
    fake_h["h"] = "e" * 64
    assert verify_chain([rec1, fake_h])[1] == "broken@2"

    # 5. Kirik zincire anchor_report fail-closed (asla ekleme yapmaz)
    ledger = tmp_path / "ledger.jsonl"
    anchor_report(legacy, ledger, ts="2026-10-05T13:00:00+00:00")
    # Zinciri elle kir
    with ledger.open("r", encoding="utf-8") as fh:
        lines = fh.readlines()
    broken_rec = json.loads(lines[0])
    broken_rec["pqri_score"] = 1.0  # h artik eslesmiyor
    with ledger.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(broken_rec, ensure_ascii=False) + "\n")

    with pytest.raises(ValueError, match="broken ledger"):
        anchor_report(ready, ledger)

    # Hala tek satir (ekleme yapilmadi)
    assert len(ledger.read_text(encoding="utf-8").strip().splitlines()) == 1
