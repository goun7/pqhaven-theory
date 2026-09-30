"""Local Filesystem, Keystore, Private Key, and Dependency Manifest Scanner.

Recursively audits source trees for:
1. X.509 PEM chains (multi-cert), DER certificates, PKCS#12 (.p12/.pfx), JKS (.jks), and private keys (.key/.pem).
2. Outdated cryptographic software dependencies (BouncyCastle, OpenSSL, legacy Python crypto).
3. Hardcoded classical algorithm calls (RSA, ECC, DES, MD5, SHA-1) in source code files (Python, Java, Go, Rust, C/C++, JS).
"""

from __future__ import annotations
import ast
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

logger = logging.getLogger(__name__)


class LocalScanner:
    """Audits local repositories and filesystem assets for cryptographic debt."""

    SKIP_DIRS = {
        ".git", ".svn", ".hg", "node_modules", "target", "build", "dist",
        "__pycache__", ".venv", "venv", ".pytest_cache", ".idea", ".vscode"
    }

    CERT_EXTS = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".jks", ".key"}
    CODE_EXTS = {".py", ".java", ".go", ".rs", ".cs", ".c", ".cpp", ".js", ".ts"}

    VULNERABLE_CODE_PATTERNS = [
        (re.compile(r"KeyPairGenerator\.getInstance\([\"']RSA[\"']", re.I), "Java RSA KeyPairGenerator", "ML-DSA-65 (FIPS 204)"),
        (re.compile(r"Cipher\.getInstance\([\"']DES", re.I), "Java DES Cipher", "AES-256-GCM"),
        (re.compile(r"RSA\.generate\(", re.I), "PyCryptodome RSA.generate", "ML-KEM / ML-DSA"),
        (re.compile(r"hashes\.(SHA1|MD5)\(\)", re.I), "Python Cryptography Weak Hash", "hashes.SHA256 / SHA3_256"),
        (re.compile(r"EVP_PKEY_RSA|RSA_generate_key_ex", re.I), "OpenSSL EVP_PKEY_RSA", "EVP_PKEY_MLKEM768 / EVP_PKEY_MLDSA65"),
        (re.compile(r"SHA1withRSA|MD5withRSA", re.I), "SHA1withRSA / MD5withRSA Signature", "ML-DSA-65 (FIPS 204)"),
        (re.compile(r"DESKeySpec|DESedeKeySpec", re.I), "Legacy DES/3DES Key Spec", "AES-256-GCM"),
        (re.compile(r"crypto/rsa|crypto/dsa", re.I), "Go crypto/rsa / crypto/dsa Import", "golang.org/x/crypto/mlkem"),
        (re.compile(r"ring::signature::RSA_", re.I), "Rust ring RSA Signature", "rustls / ml-dsa"),
        (re.compile(r"crypto\.createSign\([\"'](RSA|DSA|SHA1|MD5)", re.I), "Node.js Legacy Crypto Signer", "ML-DSA / SHA-256"),
    ]

    def scan_directory(self, root_dir: str | Path) -> List[Dict[str, Any]]:
        """Scans directory and returns detected cryptographic assets."""
        root = Path(root_dir).resolve()
        assets: List[Dict[str, Any]] = []

        if not root.exists():
            return assets

        for current_path, dirs, files in os.walk(root):
            # Prune skipped directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for file_name in files:
                file_path = Path(current_path) / file_name
                ext = file_path.suffix.lower()

                # 1. Parse Certificate, Private Key & Keystore Files
                if ext in self.CERT_EXTS:
                    cert_assets = self._inspect_cert_and_keystore_file(file_path, root)
                    assets.extend(cert_assets)

                # 2. Parse Dependency Manifests
                elif file_name in {"requirements.txt", "pom.xml", "go.mod", "Cargo.toml", "package.json"}:
                    dep_assets = self._inspect_manifest_file(file_path, root)
                    assets.extend(dep_assets)

                # 3. Parse Source Code Signatures
                elif ext in self.CODE_EXTS:
                    code_assets = self._inspect_source_file(file_path, root)
                    assets.extend(code_assets)

        return assets

    def _inspect_cert_and_keystore_file(self, file_path: Path, root: Path) -> List[Dict[str, Any]]:
        """Extracts cryptographic parameters from certificates, PKCS#12, JKS, or private keys."""
        assets: List[Dict[str, Any]] = []
        rel_path = str(file_path.relative_to(root))
        ext = file_path.suffix.lower()

        try:
            content = file_path.read_bytes()

            # 1. Handle JKS magic bytes (0xFEEDFEED)
            if ext == ".jks" or (len(content) >= 4 and content[:4] == b"\xfe\xed\xfe\xed"):
                assets.append({
                    "name": f"keystore:{rel_path}",
                    "algorithm": "JKS-Container (Legacy Java Keystore)",
                    "type": "key",
                    "key_size": 2048,
                    "location": rel_path,
                    "note": "Legacy JKS keystore detected. Migrate to PKCS#12 with ML-DSA/ML-KEM certificates."
                })
                return assets

            # 2. Handle PKCS#12 (.p12 / .pfx)
            if ext in {".p12", ".pfx"}:
                try:
                    p12_obj = pkcs12.load_pkcs12(content, password=None)
                    cert_info = "PKCS#12 Container"
                    if p12_obj.cert:
                        pub = p12_obj.cert.certificate.public_key()
                        algo = "RSA" if isinstance(pub, rsa.RSAPublicKey) else "ECDSA"
                        ksize = getattr(pub, "key_size", 2048)
                        cert_info = f"{algo}-{ksize}"
                    assets.append({
                        "name": f"pkcs12:{rel_path}",
                        "algorithm": cert_info,
                        "type": "key",
                        "key_size": 2048,
                        "location": rel_path,
                    })
                    return assets
                except Exception as exc:
                    logger.debug("Password-protected or encrypted PKCS#12 at %s: %s", rel_path, exc)
                    assets.append({
                        "name": f"pkcs12:{rel_path}",
                        "algorithm": "PKCS#12-PasswordProtected",
                        "type": "key",
                        "key_size": 2048,
                        "location": rel_path,
                    })
                    return assets

            # 3. Handle PEM Certificates (supports full multi-cert chains)
            certs = []
            try:
                certs = x509.load_pem_x509_certificates(content)
            except Exception:
                # If not PEM, try DER
                try:
                    der_cert = x509.load_der_x509_certificate(content)
                    certs = [der_cert]
                except Exception as der_exc:
                    logger.debug("File %s not parsed as DER certificate: %s", rel_path, der_exc)

            if certs:
                for idx, c in enumerate(certs):
                    pub = c.public_key()
                    algo = "Unknown"
                    ksize = 2048
                    if isinstance(pub, rsa.RSAPublicKey):
                        algo = "RSA"
                        ksize = pub.key_size
                    elif isinstance(pub, ec.EllipticCurvePublicKey):
                        algo = f"ECDSA-{pub.curve.name}"
                        ksize = pub.key_size
                    elif isinstance(pub, ed25519.Ed25519PublicKey):
                        algo = "Ed25519"
                        ksize = 256
                    elif isinstance(pub, ed448.Ed448PublicKey):
                        algo = "Ed448"
                        ksize = 448

                    suffix = f":chain-{idx}" if len(certs) > 1 else ""
                    assets.append({
                        "name": f"cert:{rel_path}{suffix}",
                        "algorithm": f"{algo}-{ksize}",
                        "type": "certificate",
                        "key_size": ksize,
                        "location": rel_path,
                        "not_after": c.not_valid_after_utc.isoformat(),
                    })
                return assets

            # 4. Handle Private Keys (.key or PEM private key blocks)
            if ext == ".key" or b"PRIVATE KEY" in content:
                try:
                    priv_key = serialization.load_pem_private_key(content, password=None)
                    algo = "Unknown"
                    ksize = 2048
                    if isinstance(priv_key, rsa.RSAPrivateKey):
                        algo = "RSA"
                        ksize = priv_key.key_size
                    elif isinstance(priv_key, ec.EllipticCurvePrivateKey):
                        algo = f"ECDSA-{priv_key.curve.name}"
                        ksize = priv_key.key_size
                    elif isinstance(priv_key, ed25519.Ed25519PrivateKey):
                        algo = "Ed25519"
                        ksize = 256
                    elif isinstance(priv_key, ed448.Ed448PrivateKey):
                        algo = "Ed448"
                        ksize = 448
                    elif isinstance(priv_key, dsa.DSAPrivateKey):
                        algo = "DSA"
                        ksize = priv_key.key_size

                    assets.append({
                        "name": f"private-key:{rel_path}",
                        "algorithm": f"{algo}-{ksize}",
                        "type": "key",
                        "key_size": ksize,
                        "location": rel_path,
                    })
                    return assets
                except TypeError:
                    # Encrypted private key requiring password
                    assets.append({
                        "name": f"private-key:{rel_path}",
                        "algorithm": "PKCS#8-EncryptedKey",
                        "type": "key",
                        "key_size": 2048,
                        "location": rel_path,
                    })
                    return assets
                except Exception as priv_exc:
                    logger.debug("File %s not a recognized private key: %s", rel_path, priv_exc)

        except Exception as exc:
            logger.warning("Error inspecting cert/keystore file %s: %s", rel_path, exc)

        return assets

    def _inspect_manifest_file(self, file_path: Path, root: Path) -> List[Dict[str, Any]]:
        """Detects outdated cryptographic libraries in dependency manifests."""
        assets: List[Dict[str, Any]] = []
        rel_path = str(file_path.relative_to(root))
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            lower = text.lower()
            if "bouncycastle" in lower or "bcprov" in lower:
                assets.append({
                    "name": f"dep:{rel_path}:bouncycastle",
                    "algorithm": "RSA-2048",
                    "type": "algorithm",
                    "key_size": 2048,
                    "location": rel_path,
                    "note": "Legacy BouncyCastle dependency detected without verified FIPS 203/204 provider."
                })
            if "pycrypto" in lower:
                assets.append({
                    "name": f"dep:{rel_path}:pycrypto",
                    "algorithm": "DES-56",
                    "type": "algorithm",
                    "key_size": 56,
                    "location": rel_path,
                    "note": "Deprecated pycrypto library detected."
                })
            if "openssl" in lower and ("1.0" in text or "1.1" in text):
                assets.append({
                    "name": f"dep:{rel_path}:openssl_legacy",
                    "algorithm": "RSA-2048",
                    "type": "algorithm",
                    "key_size": 2048,
                    "location": rel_path,
                    "note": "Legacy OpenSSL 1.x reference detected."
                })
        except Exception as exc:
            logger.warning("Error inspecting dependency manifest %s: %s", rel_path, exc)
        return assets

    def _inspect_source_file(self, file_path: Path, root: Path) -> List[Dict[str, Any]]:
        """Searches source code for hardcoded classical cryptographic calls and data-flow taint."""
        assets: List[Dict[str, Any]] = []
        rel_path = str(file_path.relative_to(root))
        try:
            if file_path.stat().st_size > 1024 * 1024:
                return assets

            raw_text = file_path.read_text(encoding="utf-8", errors="ignore")

            # 1. Regex Pattern Matching across all source languages
            for line_idx, line in enumerate(raw_text.splitlines(), 1):
                for pattern, label, replacement in self.VULNERABLE_CODE_PATTERNS:
                    if pattern.search(line):
                        assets.append({
                            "name": f"code:{rel_path}:{line_idx}",
                            "algorithm": "RSA-2048" if "RSA" in label else ("DES-56" if "DES" in label else "AES-128"),
                            "type": "algorithm",
                            "key_size": 2048 if "RSA" in label else 128,
                            "location": f"{rel_path}:{line_idx}",
                            "finding": label,
                            "replacement": replacement
                        })

            # 2. Python Semantic AST Taint Analysis (Data-Flow Tracking)
            if file_path.suffix == ".py":
                try:
                    tree = ast.parse(raw_text, filename=rel_path)
                    visitor = CryptoTaintVisitor(rel_path)
                    visitor.visit(tree)
                    assets.extend(visitor.findings)
                except SyntaxError:
                    pass
        except Exception as exc:
            logger.warning("Error inspecting source file %s: %s", rel_path, exc)
        return assets


class CryptoTaintVisitor(ast.NodeVisitor):
    """Traces cryptographic variable instantiation and semantic data-flow taint propagation."""

    TAINT_SOURCES = {
        "RSA.generate",
        "generate_private_key",
        "load_pem_private_key",
        "load_der_private_key",
        "DES.new",
        "ARC4.new",
        "Cipher",
    }

    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.tainted_vars: Dict[str, Dict[str, Any]] = {}
        self.findings: List[Dict[str, Any]] = []

    def visit_Assign(self, node: ast.Assign):
        # 1. Direct Taint Instantiation
        call_name = self._get_call_name(node.value)
        if call_name:
            for src in self.TAINT_SOURCES:
                if src in call_name:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            self.tainted_vars[var_name] = {
                                "source_call": call_name,
                                "line": node.lineno,
                                "var_name": var_name,
                            }
                            self.findings.append({
                                "name": f"taint:{self.rel_path}:{node.lineno}:{var_name}",
                                "algorithm": "RSA-2048" if "RSA" in call_name or "rsa" in call_name else "DES-56",
                                "type": "algorithm",
                                "key_size": 2048 if "RSA" in call_name or "rsa" in call_name else 56,
                                "location": f"{self.rel_path}:{node.lineno}",
                                "finding": f"Tainted Crypto Source: Variable '{var_name}' instantiated via {call_name}",
                                "replacement": "ML-KEM-768 / ML-DSA-65 (NIST FIPS 203/204)",
                                "taint_origin": call_name,
                            })

        # 2. Taint Data-Flow Propagation (e.g., signer = PKCS1_v1_5.new(key))
        if isinstance(node.value, ast.Call):
            used_taints = [arg.id for arg in node.value.args if isinstance(arg, ast.Name) and arg.id in self.tainted_vars]
            if used_taints:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        child_var = target.id
                        parent_var = used_taints[0]
                        parent_info = self.tainted_vars[parent_var]
                        self.tainted_vars[child_var] = {
                            "source_call": f"propagated_from_{parent_var}",
                            "line": node.lineno,
                            "var_name": child_var,
                        }
                        self.findings.append({
                            "name": f"taint-flow:{self.rel_path}:{node.lineno}:{child_var}",
                            "algorithm": "RSA-2048",
                            "type": "algorithm",
                            "key_size": 2048,
                            "location": f"{self.rel_path}:{node.lineno}",
                            "finding": f"Tainted Crypto Flow: Variable '{child_var}' derived from tainted key '{parent_var}'",
                            "replacement": "ML-DSA-65 Signature Engine",
                            "taint_origin": parent_info["source_call"],
                        })

        self.generic_visit(node)

    def _get_call_name(self, node: ast.AST) -> Optional[str]:
        if not isinstance(node, ast.Call):
            return None
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            parts = []
            curr = func
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            return ".".join(reversed(parts))
        return None



