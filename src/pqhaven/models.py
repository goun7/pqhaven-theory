"""Data models, risk calculation, and attestation structures for PQHaven."""

from __future__ import annotations
from enum import Enum
import math
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PqcRiskGrade(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    TRANSITIONAL = "TRANSITIONAL"
    READY = "READY"


class CryptoAssetType(str, Enum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    KEY = "key"


class CryptoProperties(BaseModel):
    model_config = {"populate_by_name": True}
    asset_type: CryptoAssetType = Field(..., alias="assetType")
    algorithm_name: Optional[str] = Field(None, alias="algorithmName")
    key_size: Optional[int] = Field(None, alias="keySize")
    nist_quantum_level: int = Field(0, alias="nistQuantumSecurityLevel")
    shor_vulnerable: bool = Field(True, alias="shorVulnerable")
    grover_degraded: bool = Field(False, alias="groverDegraded")
    recommended_replacement: str = Field(..., alias="recommendedReplacement")
    oid: Optional[str] = None


class CryptoComponent(BaseModel):
    model_config = {"populate_by_name": True}
    name: str
    bom_ref: str = Field(..., alias="bom-ref")
    component_type: str = Field("cryptographic-asset", alias="type")
    crypto_properties: CryptoProperties = Field(..., alias="cryptoProperties")


class CbomMetadata(BaseModel):
    model_config = {"populate_by_name": True}
    timestamp: str
    tools: List[Dict[str, str]] = Field(default_factory=list)
    component: Optional[Dict[str, Any]] = None


class CbomDependency(BaseModel):
    model_config = {"populate_by_name": True}
    ref: str
    depends_on: List[str] = Field(default_factory=list, alias="dependsOn")


class CycloneDxCbom(BaseModel):
    model_config = {"populate_by_name": True}
    bom_format: str = Field("CycloneDX", alias="bomFormat")
    spec_version: str = Field("1.6", alias="specVersion")
    serial_number: str = Field(..., alias="serialNumber")
    version: int = 1
    metadata: Optional[CbomMetadata] = None
    components: List[CryptoComponent] = Field(default_factory=list)
    dependencies: List[CbomDependency] = Field(default_factory=list)


class AssessmentReport(BaseModel):
    target: str
    pqri_score: float
    overall_grade: PqcRiskGrade
    cbom: CycloneDxCbom
    hndl_vulnerability_count: int
    compliance_flags: List[str] = Field(default_factory=list)
    merkle_root: Optional[str] = None


class MonteCarloReport(BaseModel):
    iterations: int
    vulnerability_probability: float
    mean_shelf_life_years: float
    mean_migration_time_years: float
    mean_crqc_arrival_years: float
    confidence_interval_95: List[float]
    distribution_bins: List[Dict[str, Any]] = Field(default_factory=list)


class VerifiableCredentialAttestation(BaseModel):
    context: List[str] = Field(
        default=["https://www.w3.org/ns/credentials/v2", "https://schema.pqhaven.io/pqc-attestation/v1"],
        alias="@context"
    )
    id: str
    type: List[str] = Field(default=["VerifiableCredential", "PqcPostureAttestation"])
    issuer: str
    valid_from: str = Field(..., alias="validFrom")
    credential_subject: Dict[str, Any] = Field(..., alias="credentialSubject")
    proof: Dict[str, Any]


def calculate_mosca_pqri(
    shelf_life_years: float,
    migration_time_years: float,
    crqc_arrival_years: float,
    exposure_factor: float = 0.8,
    legacy_density: float = 0.9,
    alpha: float = 2.5,
    beta: float = 1.8,
    gamma: float = 1.2,
) -> float:
    """Calculates normalized Post-Quantum Risk Index (PQRI) [0-100].

    Formula: PQRI = 100 / (1 + exp(-(alpha * (X + Y - Z)/Z + beta * H + gamma * C)))
    """
    if crqc_arrival_years <= 0:
        return 100.0

    time_pressure = (shelf_life_years + migration_time_years - crqc_arrival_years) / crqc_arrival_years
    logit = alpha * time_pressure + beta * exposure_factor + gamma * legacy_density

    # Sigmoid function scaled to 0-100
    score = 100.0 / (1.0 + math.exp(-logit))
    return round(float(score), 2)


def grade_pqri(score: float) -> PqcRiskGrade:
    """Classifies risk grade based on PQRI score."""
    if score >= 75.0:
        return PqcRiskGrade.CRITICAL
    elif score >= 50.0:
        return PqcRiskGrade.HIGH
    elif score >= 25.0:
        return PqcRiskGrade.TRANSITIONAL
    return PqcRiskGrade.READY
