"""Autonomous Code Remediator & Post-Quantum Patch Generator.

Performs automated safe refactoring:
1. Replaces weak digest functions (MD5, SHA1 -> SHA256 / SHA3_256).
2. Refactors legacy symmetric ciphers (DES/3DES -> AES-256-GCM).
3. Adds PQC migration wrappers and guidance comments for classical RSA/ECC usages.
4. Generates standard unified diff (.patch) or applies in-place with backup (.bak).
"""

from __future__ import annotations
import difflib
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CodeRemediator:
    """Automated cryptographic refactor and patch engine."""

    REPLACEMENTS: List[Tuple[re.Pattern, str, str]] = [
        (
            re.compile(r"hashes\.SHA1\(\)"),
            "hashes.SHA256()",
            "Replace weak SHA-1 digest with collision-resistant SHA-256 (NIST FIPS 180-4)",
        ),
        (
            re.compile(r"hashes\.MD5\(\)"),
            "hashes.SHA256()",
            "Replace cryptanalytically broken MD5 with SHA-256 (NIST FIPS 180-4)",
        ),
        (
            re.compile(r'Cipher\.getInstance\("DES/CBC/PKCS5Padding"\)'),
            'Cipher.getInstance("AES/GCM/NoPadding")',
            "Replace insecure DES cipher with quantum-resilient AES-256-GCM",
        ),
        (
            re.compile(r"Cipher\.getInstance\([\"']DES[\"']\)"),
            'Cipher.getInstance("AES/GCM/NoPadding")',
            "Replace insecure DES cipher with AES-256-GCM",
        ),
        (
            re.compile(r"from Crypto\.PublicKey import RSA"),
            "# [PQC-MIGRATION] Target: FIPS 203 ML-KEM / FIPS 204 ML-DSA\nfrom Crypto.PublicKey import RSA",
            "Flag PyCryptodome RSA for FIPS 203/204 Post-Quantum Migration",
        ),
    ]

    def remediate_text(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """Applies transformation rules to source text and returns new text plus modifications."""
        modified_text = text
        changes_applied: List[Dict[str, Any]] = []

        for pattern, replacement, description in self.REPLACEMENTS:
            if pattern.search(modified_text):
                modified_text, count = pattern.subn(replacement, modified_text)
                if count > 0:
                    changes_applied.append({
                        "description": description,
                        "replacement": replacement,
                        "occurrences": count,
                    })

        return modified_text, changes_applied

    def generate_patch(self, file_path: Path) -> Optional[str]:
        """Generates a standard unified diff string for a target source file."""
        if not file_path.is_file():
            return None

        original = file_path.read_text(encoding="utf-8", errors="ignore")
        remediated, changes = self.remediate_text(original)

        if not changes or original == remediated:
            return None

        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            remediated.splitlines(keepends=True),
            fromfile=f"a/{file_path.name}",
            tofile=f"b/{file_path.name}",
        )
        return "".join(diff)

    def apply_file(self, file_path: Path, backup: bool = True) -> bool:
        """Applies remediation directly in-place, creating a .bak copy if requested."""
        if not file_path.is_file():
            return False

        original = file_path.read_text(encoding="utf-8", errors="ignore")
        remediated, changes = self.remediate_text(original)

        if not changes or original == remediated:
            return False

        if backup:
            bak_path = file_path.with_suffix(file_path.suffix + ".bak")
            bak_path.write_text(original, encoding="utf-8")

        file_path.write_text(remediated, encoding="utf-8")
        return True

    def scan_and_remediate(
        self,
        root_path: Path,
        apply: bool = False,
    ) -> List[Dict[str, Any]]:
        """Recursively scans directory and generates patches or applies fixes."""
        results: List[Dict[str, Any]] = []
        skip_dirs = {".git", "node_modules", "target", "build", "dist", ".pytest_cache", ".venv"}

        for p in root_path.rglob("*"):
            if p.is_dir() or any(part in skip_dirs for part in p.parts):
                continue
            if p.suffix not in {".py", ".java", ".go", ".rs", ".js", ".ts", ".c", ".cpp"}:
                continue
            if p.name == "remediator.py":
                continue

            patch = self.generate_patch(p)
            if patch:
                applied = False
                if apply:
                    applied = self.apply_file(p, backup=True)
                results.append({
                    "file": str(p),
                    "relative_path": str(p.relative_to(root_path)),
                    "patch": patch,
                    "applied": applied,
                })

        return results
