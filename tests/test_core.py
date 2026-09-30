"""Comprehensive tests for PQHaven core models, engine, and Mosca equations."""

import pytest
from pqhaven.models import (
    PqcRiskGrade,
    calculate_mosca_pqri,
    grade_pqri,
)
from pqhaven.engine import PQScanEngine


def test_mosca_pqri_calculation_and_grading():
    # When shelf life (15) + migration (4) >> crqc (7) -> Highly vulnerable
    score_high = calculate_mosca_pqri(
        shelf_life_years=15.0,
        migration_time_years=4.0,
        crqc_arrival_years=7.0,
        exposure_factor=1.0,
        legacy_density=1.0,
    )
    assert score_high >= 75.0
    assert grade_pqri(score_high) == PqcRiskGrade.CRITICAL

    # When shelf life is short (1 yr) and CRQC is far (15 yrs) -> Ready/safe
    score_low = calculate_mosca_pqri(
        shelf_life_years=1.0,
        migration_time_years=1.0,
        crqc_arrival_years=15.0,
        exposure_factor=0.1,
        legacy_density=0.1,
    )
    assert score_low < 30.0
    assert grade_pqri(score_low) in (PqcRiskGrade.READY, PqcRiskGrade.TRANSITIONAL)

    # Edge cases
    assert calculate_mosca_pqri(10, 3, 0) == 100.0
    assert grade_pqri(55.0) == PqcRiskGrade.HIGH
    assert grade_pqri(35.0) == PqcRiskGrade.TRANSITIONAL
    assert grade_pqri(10.0) == PqcRiskGrade.READY


def test_engine_assessment_with_legacy_and_pqc():
    engine = PQScanEngine()
    assets = [
        {"name": "web-cert", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048},
        {"name": "kex", "algorithm": "ML-KEM-768", "type": "protocol", "key_size": 768},
        {"name": "db-enc", "algorithm": "AES-128", "type": "algorithm", "key_size": 128},
        {"name": "legacy-bank", "algorithm": "RSA-1024", "type": "certificate", "key_size": 1024},
        {"name": "broken-hash", "algorithm": "MD5", "type": "algorithm", "key_size": 128},
    ]

    report = engine.assess_target("api.test.com", assets)
    assert report.target == "api.test.com"
    assert len(report.cbom.components) == 5
    assert report.cbom.spec_version == "1.6"
    assert report.cbom.metadata is not None
    assert len(report.cbom.dependencies) == 5
    assert report.hndl_vulnerability_count >= 1
    assert "KVKK_MADDE_12_HNDL_VIOLATION_RISK" in report.compliance_flags
    assert "BDDK_MADDE_16_DEPRECATED_ALGO" in report.compliance_flags
    assert "CNSA_2_0_EXPIRATION_WARNING_2030" in report.compliance_flags
    assert report.pqri_score > 0
    assert report.merkle_root is not None
    assert len(report.merkle_root) == 64


def test_engine_all_pqc_ready():
    engine = PQScanEngine()
    assets = [
        {"name": "web-kex", "algorithm": "ML-KEM-768", "type": "protocol", "key_size": 768},
        {"name": "code-sign", "algorithm": "ML-DSA-65", "type": "algorithm", "key_size": 192},
        {"name": "hybrid-tls", "algorithm": "X25519MLKEM768", "type": "protocol", "key_size": 768},
        {"name": "hash-sig", "algorithm": "SLH-DSA-SHA2-128s", "type": "algorithm", "key_size": 128},
        {"name": "fft-sig", "algorithm": "FN-DSA-512", "type": "algorithm", "key_size": 512},
        {"name": "mceliece", "algorithm": "Classic-McEliece-348864", "type": "algorithm", "key_size": 348864},
    ]

    report = engine.assess_target(
        "safe.internal",
        assets,
        shelf_life_years=2.0,
        migration_time_years=1.0,
        crqc_arrival_years=10.0,
    )
    assert report.hndl_vulnerability_count == 0
    assert len(report.compliance_flags) == 0
    assert report.overall_grade in (PqcRiskGrade.READY, PqcRiskGrade.TRANSITIONAL)


def test_engine_monte_carlo_simulation():
    engine = PQScanEngine()
    mc = engine.run_monte_carlo(iterations=2000, seed=42)
    assert mc.iterations == 2000
    assert 0.0 <= mc.vulnerability_probability <= 1.0
    assert mc.mean_shelf_life_years > 0
    assert mc.mean_migration_time_years > 0
    assert mc.mean_crqc_arrival_years > 0
    assert len(mc.confidence_interval_95) == 2
    assert mc.confidence_interval_95[0] <= mc.vulnerability_probability <= mc.confidence_interval_95[1]
    assert len(mc.distribution_bins) == 10


def test_engine_merkle_root_and_w3c_vc():
    engine = PQScanEngine()
    # Empty CBOM Merkle Root
    from pqhaven.models import CycloneDxCbom
    empty_cbom = CycloneDxCbom(serialNumber="urn:uuid:test-empty", components=[])
    root_empty = engine.compute_cbom_merkle_root(empty_cbom)
    assert isinstance(root_empty, str)
    assert len(root_empty) == 64

    # W3C VC generation
    assets = [
        {"name": "pqc-kem", "algorithm": "ML-KEM-1024", "type": "protocol", "key_size": 1024},
        {"name": "pqc-dsa", "algorithm": "ML-DSA-87", "type": "algorithm", "key_size": 256},
    ]
    report = engine.assess_target("attest.internal", assets)
    vc = engine.generate_verifiable_credential(report, issuer_did="did:pqhaven:auditor:0xTEST")

    assert vc.issuer == "did:pqhaven:auditor:0xTEST"
    assert "VerifiableCredential" in vc.type
    assert vc.credential_subject["targetEndpoint"] == "attest.internal"
    assert vc.credential_subject["onChainRegistryContract"] == "0x446B847e096B408B48B4bEeeFd0F4D3C23B99511"
    assert vc.proof["type"] == "Ed25519Signature2020"
    assert vc.proof["proofValue"].startswith("0x")

