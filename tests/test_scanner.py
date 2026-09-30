"""Tests for local filesystem, certificate, and dependency scanning."""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pqhaven.scanner import LocalScanner


def test_local_scanner_with_real_files(tmp_path: Path):
    # 1. Generate a real self-signed RSA certificate file
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test-local.internal")
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)) # 10 years -> >2030
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "server.crt"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # 2. Create a dummy manifest file
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("bouncycastle-old==1.46\npycrypto==2.6.1\n", encoding="utf-8")

    # 3. Create a python file with legacy crypto call
    code_file = tmp_path / "service.py"
    code_file.write_text("import RSA\nkey = RSA.generate(2048)\n", encoding="utf-8")

    # Run scanner
    scanner = LocalScanner()
    assets = scanner.scan_directory(tmp_path)

    assert len(assets) >= 3
    algo_names = [a["algorithm"] for a in assets]
    assert any("RSA-2048" in a for a in algo_names)
    assert any("DES-56" in a for a in algo_names)


def test_scanner_formats_and_edge_cases(tmp_path: Path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import pkcs12

    # 1. JKS file with magic bytes 0xFEEDFEED
    jks_file = tmp_path / "keystore.jks"
    jks_file.write_bytes(b"\xfe\xed\xfe\xed\x00\x00\x00\x02\x00")

    # 2. DER encoded ECDSA certificate
    key_ec = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ecdsa.test")])
    cert_ec = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key_ec.public_key())
        .serial_number(777)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100))
        .sign(key_ec, hashes.SHA256())
    )
    der_file = tmp_path / "ec.der"
    der_file.write_bytes(cert_ec.public_bytes(serialization.Encoding.DER))

    # 3. PKCS#12 file
    p12_bytes = pkcs12.serialize_key_and_certificates(
        b"cert-alias",
        key_ec,
        cert_ec,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p12_file = tmp_path / "bundle.p12"
    p12_file.write_bytes(p12_bytes)

    # 4. Password-protected PKCS#12 simulation (raw bytes that fail passwordless load)
    p12_enc_file = tmp_path / "protected.pfx"
    p12_enc_file.write_bytes(b"\x30\x82\x01\x00" + b"\x00" * 200)

    # 5. Manifest with OpenSSL 1.0
    dep_file = tmp_path / "pom.xml"
    dep_file.write_text("<dependency>openssl-1.0.2</dependency>\n", encoding="utf-8")

    # 6. Source file with Go crypto/rsa
    src_file = tmp_path / "crypto.go"
    src_file.write_text('import "crypto/rsa"\n', encoding="utf-8")

    # 7. File > 1MB ignored
    big_file = tmp_path / "huge.py"
    big_file.write_bytes(b"# " + b"A" * (1024 * 1024 + 10))

    scanner = LocalScanner()
    assets = scanner.scan_directory(tmp_path)

    asset_names = [a["name"] for a in assets]
    assert any("keystore:keystore.jks" in n for n in asset_names)
    assert any("cert:ec.der" in n for n in asset_names)
    assert any("pkcs12:bundle.p12" in n for n in asset_names)
    assert any("pkcs12:protected.pfx" in n for n in asset_names)
    assert any("dep:pom.xml:openssl_legacy" in n for n in asset_names)
    assert any("crypto.go" in n for n in asset_names)


def test_scanner_multi_cert_pem_and_private_keys(tmp_path: Path):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    # 1. Multi-cert chain PEM
    key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key2 = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.datetime.now(datetime.timezone.utc)
    c1 = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "leaf.int")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ca.int")]))
        .public_key(key1.public_key())
        .serial_number(101)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key2, hashes.SHA256())
    )
    c2 = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ca.int")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "root.int")]))
        .public_key(key2.public_key())
        .serial_number(102)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=730))
        .sign(key2, hashes.SHA256())
    )
    chain_pem = c1.public_bytes(serialization.Encoding.PEM) + c2.public_bytes(serialization.Encoding.PEM)
    (tmp_path / "chain.pem").write_bytes(chain_pem)

    # 2. Private Key file (.key)
    priv_ed = ed25519.Ed25519PrivateKey.generate()
    (tmp_path / "server.key").write_bytes(priv_ed.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

    # 3. Source code with Java & Python vulnerable patterns
    (tmp_path / "SecurityConfig.java").write_text(
        'KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");\n'
        'Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");\n',
        encoding="utf-8"
    )

    scanner = LocalScanner()
    assets = scanner.scan_directory(tmp_path)

    names = [a["name"] for a in assets]
    assert any("chain:chain.pem:chain-0" in n or "cert:chain.pem:chain-0" in n for n in names)
    assert any("private-key:server.key" in n for n in names)
    assert any("SecurityConfig.java" in n for n in names)


def test_scanner_encrypted_private_key_and_edge_cases(tmp_path: Path):
    from cryptography.hazmat.primitives.asymmetric import ec

    # 1. Non-existent directory
    scanner = LocalScanner()
    assert scanner.scan_directory(tmp_path / "does_not_exist") == []

    # 2. Encrypted private key
    priv_ec = ec.generate_private_key(ec.SECP384R1())
    enc_key_bytes = priv_ec.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret123")
    )
    (tmp_path / "enc.key").write_bytes(enc_key_bytes)

    # 3. Unencrypted EC private key (.pem)
    unenc_key_bytes = priv_ec.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    (tmp_path / "ec_priv.pem").write_bytes(unenc_key_bytes)

    assets = scanner.scan_directory(tmp_path)
    algos = [a["algorithm"] for a in assets]
    assert "PKCS#8-EncryptedKey" in algos
    assert any("ECDSA-secp384r1" in a for a in algos)


def test_scanner_dsa_and_unrecognized_key(tmp_path: Path):
    from cryptography.hazmat.primitives.asymmetric import dsa

    # DSA private key
    priv_dsa = dsa.generate_private_key(key_size=2048)
    dsa_bytes = priv_dsa.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    (tmp_path / "dsa.key").write_bytes(dsa_bytes)

    # Corrupt key file
    (tmp_path / "corrupt.key").write_bytes(b"-----BEGIN PRIVATE KEY-----\nINVALID_DATA\n-----END PRIVATE KEY-----")

    scanner = LocalScanner()
    assets = scanner.scan_directory(tmp_path)
    algos = [a["algorithm"] for a in assets]
    assert any("DSA-2048" in a for a in algos)


def test_scanner_ed25519_ed448_and_keys(tmp_path: Path):
    from cryptography.hazmat.primitives.asymmetric import ed25519, ed448

    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Ed25519 Certificate
    priv_ed25519 = ed25519.Ed25519PrivateKey.generate()
    cert_ed25519 = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ed25519.test")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ed25519.test")]))
        .public_key(priv_ed25519.public_key())
        .serial_number(123)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=100))
        .sign(priv_ed25519, None)
    )
    (tmp_path / "ed25519.crt").write_bytes(cert_ed25519.public_bytes(serialization.Encoding.PEM))

    # 2. Ed448 Certificate
    priv_ed448 = ed448.Ed448PrivateKey.generate()
    cert_ed448 = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ed448.test")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ed448.test")]))
        .public_key(priv_ed448.public_key())
        .serial_number(124)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=100))
        .sign(priv_ed448, None)
    )
    (tmp_path / "ed448.crt").write_bytes(cert_ed448.public_bytes(serialization.Encoding.PEM))

    # 3. RSA Private Key File (.key)
    priv_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "rsa_private.key").write_bytes(priv_rsa.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

    # 4. Ed448 Private Key File (.key)
    (tmp_path / "ed448_private.key").write_bytes(priv_ed448.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

    scanner = LocalScanner()
    assets = scanner.scan_directory(tmp_path)
    algos = [a["algorithm"] for a in assets]
    assert any("Ed25519-256" in a for a in algos)
    assert any("Ed448-448" in a for a in algos)
    assert any("RSA-2048" in a for a in algos)


def test_python_ast_taint_analysis(tmp_path: Path):
    py_code = (
        "from Crypto.PublicKey import RSA\n"
        "from Crypto.Cipher import PKCS1_OAEP\n"
        "\n"
        "master_key = RSA.generate(2048)\n"
        "cipher_inst = PKCS1_OAEP.new(master_key)\n"
        "result = cipher_inst.encrypt(b'secret')\n"
    )
    (tmp_path / "crypto_flow.py").write_text(py_code, encoding="utf-8")

    scanner = LocalScanner()
    assets = scanner.scan_directory(tmp_path)

    findings = [a["finding"] for a in assets if "finding" in a]
    assert any("Tainted Crypto Source: Variable 'master_key'" in f for f in findings)
    assert any("Tainted Crypto Flow: Variable 'cipher_inst' derived from tainted key 'master_key'" in f for f in findings)






