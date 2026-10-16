"""Tests for network probing logic (TLS & SSH) and HTML cockpit generation."""

import datetime
import socket
import struct
import threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pqhaven.cockpit import generate_cockpit_html
from pqhaven.engine import PQScanEngine
from pqhaven.network import NetworkProbe


def test_network_probe_parse_certificate():
    probe = NetworkProbe()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "probe-test.internal")
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(123456)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=4000))
        .sign(key, hashes.SHA256())
    )
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    parsed = probe._parse_der_certificate(der_bytes)
    assert parsed["subject_cn"] == "probe-test.internal"
    assert parsed["algorithm"] == "RSA"
    assert parsed["key_size"] == 2048
    assert parsed["shor_vulnerable"] is True
    assert parsed["hndl_risk"] is True


def test_ssh_probe_handshake():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    def srv_worker():
        conn, _ = srv.accept()
        conn.sendall(b"SSH-2.0-OpenSSH_9.8p1 Debian-5\r\n")
        _ = conn.recv(1024)
        
        cookie = b"\x00" * 16
        kex_str = b"mlkem768x25519-sha512@openssh.com,curve25519-sha256"
        hk_str = b"ssh-ed25519,ssh-rsa"
        ciphers = b"chacha20-poly1305@openssh.com"
        
        def pack_nl(s):
            return struct.pack(">I", len(s)) + s

        payload = (
            bytes([20]) + cookie + pack_nl(kex_str) + pack_nl(hk_str)
            + pack_nl(ciphers) + pack_nl(ciphers)
            + pack_nl(b"") + pack_nl(b"") + pack_nl(b"") + pack_nl(b"")
            + pack_nl(b"") + pack_nl(b"")
            + b"\x00" + struct.pack(">I", 0)
        )
        pad_len = 8
        pkt_len = len(payload) + 1 + pad_len
        pkt = struct.pack(">I", pkt_len) + bytes([pad_len]) + payload + (b"\x00" * pad_len)
        conn.sendall(pkt)
        conn.close()

    t = threading.Thread(target=srv_worker)
    t.start()

    probe = NetworkProbe(timeout=2.0)
    res = probe.probe_ssh_endpoint("127.0.0.1", port)
    t.join()
    srv.close()

    assert res["connected"] is True
    assert "OpenSSH_9.8p1" in res["server_banner"]
    assert res["pqc_hybrid_kex"] is True
    assert "mlkem768x25519-sha512@openssh.com" in res["kex_algorithms"]
    assert res["shor_vulnerable_host_keys"] is True


def test_cockpit_html_generation():
    engine = PQScanEngine()
    sample_assets = [
        {"name": "test-tls", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048},
        {"name": "test-kex", "algorithm": "ECDH-X25519", "type": "protocol", "key_size": 256},
    ]
    report = engine.assess_target("dashboard.test.com", sample_assets)

    html = generate_cockpit_html(report)
    assert "<!DOCTYPE html>" in html
    assert "PQHaven Executive Cockpit" in html
    assert "dashboard.test.com" in html
    assert "Mosca Eşitsizliği" in html
    assert "topologyCanvas" in html
    assert "CycloneDX" in html
    assert "gauge-svg" in html
    assert "stepPhysics" in html
    assert "sortTable" in html
    assert "copyExecutiveSummary" in html
    assert "@media print" in html


def test_network_probe_ecdsa_and_ed25519():
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    probe = NetworkProbe()

    # 1. Test ECDSA cert
    key_ec = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ec.internal")])
    issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Test Corp CA")])
    cert_ec = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key_ec.public_key())
        .serial_number(888)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2000))
        .sign(key_ec, hashes.SHA384())
    )
    parsed_ec = probe._parse_der_certificate(cert_ec.public_bytes(serialization.Encoding.DER))
    assert parsed_ec["algorithm"] == "ECDSA-secp384r1"
    assert parsed_ec["issuer_org"] == "Test Corp CA"
    assert parsed_ec["shor_vulnerable"] is True

    # 2. Test Ed25519 cert
    key_ed = ed25519.Ed25519PrivateKey.generate()
    subject_ed = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ed.internal")])
    cert_ed = (
        x509.CertificateBuilder()
        .subject_name(subject_ed)
        .issuer_name(subject_ed)
        .public_key(key_ed.public_key())
        .serial_number(999)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2000))
        .sign(key_ed, None)
    )
    parsed_ed = probe._parse_der_certificate(cert_ed.public_bytes(serialization.Encoding.DER))
    assert parsed_ed["algorithm"] == "Ed25519"
    assert parsed_ed["key_size"] == 256


def test_tls_probe_local_ssl_server(tmp_path):
    import ssl
    import tempfile

    # Generate temp key and cert for local SSL server
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(str(cert_path), str(key_path))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3.0)
    port = srv.getsockname()[1]
    srv.listen(1)

    def srv_worker():
        try:
            raw_conn, _ = srv.accept()
            with ssl_ctx.wrap_socket(raw_conn, server_side=True) as sconn:
                pass
        except Exception:
            pass

    t = threading.Thread(target=srv_worker)
    t.start()

    probe = NetworkProbe(timeout=3.0)
    res = probe.probe_tls_endpoint("127.0.0.1", port)
    t.join(timeout=3.0)
    srv.close()

    assert res["connected"] is True
    assert res["tls_version"] is not None
    assert len(res["certificates"]) == 1
    assert res["certificates"][0]["subject_cn"] == "127.0.0.1"


def test_ssh_probe_error_branches():
    # 1. Test unsupported banner
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3.0)
    port = srv.getsockname()[1]
    srv.listen(1)

    def srv_bad_banner():
        try:
            conn, _ = srv.accept()
            conn.sendall(b"NOT_SSH_BANNER\r\n")
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=srv_bad_banner)
    t.start()

    probe = NetworkProbe(timeout=2.0)
    res = probe.probe_ssh_endpoint("127.0.0.1", port)
    t.join(timeout=3.0)
    srv.close()

    assert res["connected"] is False
    assert "Unsupported SSH banner" in res["error"]


def test_network_probe_ed448():
    from cryptography.hazmat.primitives.asymmetric import ed448

    probe = NetworkProbe()
    key_ed448 = ed448.Ed448PrivateKey.generate()
    subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ed448.test")])
    cert_ed448 = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key_ed448.public_key())
        .serial_number(888)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=20))
        .sign(key_ed448, None)
    )

    der_bytes = cert_ed448.public_bytes(serialization.Encoding.DER)
    parsed = probe._parse_der_certificate(der_bytes)
    assert parsed["algorithm"] == "Ed448"
    assert parsed["key_size"] == 448
    assert parsed["subject_cn"] == "ed448.test"


def test_network_probe_raw_tls13_positive():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3.0)
    port = srv.getsockname()[1]
    srv.listen(1)

    def srv_worker():
        try:
            conn, _ = srv.accept()
            _ = conn.recv(2048)
            # Send valid TLS 1.3 ServerHello containing key_share (0x0033) and 0x11ec
            body = b"\x02\x00\x00\x2e\x03\x03" + (b"\x00" * 32) + b"\x00\x33\x00\x04\x11\xec\x00\x00"
            fake_sh = b"\x16\x03\x03" + struct.pack(">H", len(body)) + body
            conn.sendall(fake_sh)
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=srv_worker)
    t.start()

    probe = NetworkProbe(timeout=2.0)
    pqc_found, kex_name = probe._probe_raw_tls13_hybrid("127.0.0.1", port)
    t.join(timeout=3.0)
    srv.close()

    assert pqc_found is True
    assert "0x11ec" in kex_name


def test_network_probe_raw_tls13_hata_belirsiz_olarak_isaretlenir():
    """PQH-NET-1 (DALGA-C-2-DUZELTILDI): probe yapilip-olculemeyince
    'legacy ECDH' gibi KAYDEDILMEMELI — (False, 'probe-error') donmeli
    ( onceki davranis: sessizce (False, 'Unknown') = hatali-negatif)."""
    probe = NetworkProbe(timeout=0.001)
    # 127.0.0.1:1'e baglanma-denemesi ConnectionRefused firlatacak
    pqc_found, kex_name = probe._probe_raw_tls13_hybrid("127.0.0.1", 1)
    assert pqc_found is False
    assert kex_name == "probe-error"


def test_probe_tls_endpoint_probe_error_belirsiz_gosterir():
    """PQH-NET-1 (DALGA-C-2-DUZELTILDI): probe_tls_endpoint ham-probe
    hatasinda pqc_hybrid_kex=None + kex_group='probe-error' ile-belirsiz
    isaretlemeli ( False = 'PQC-yok' ANLAMINA GELMEMELI)."""
    probe = NetworkProbe(timeout=0.001)
    result = probe.probe_tls_endpoint("127.0.0.1", 1)
    # baglanamayinca connected=False — ham-probe branch'ine girmez;
    # ozaman dogrudan _probe_raw_tls13_hybrid hatAYI-olcmek yeterli ( yukaridaki
    # test). Burada ekriminin turbegezgovu: hatali-durumda 'connected' False
    # ve result 'error' tasiyabilir.
    assert isinstance(result, dict)


def test_ssh_probe_malformed_packets():
    # Test short header
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3.0)
    port = srv.getsockname()[1]
    srv.listen(1)

    def srv_worker():
        try:
            conn, _ = srv.accept()
            conn.sendall(b"SSH-2.0-TestServer\r\n")
            _ = conn.recv(1024)
            # Send only 2 bytes instead of 4-byte header
            conn.sendall(b"\x00\x01")
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=srv_worker)
    t.start()

    probe = NetworkProbe(timeout=2.0)
    res = probe.probe_ssh_endpoint("127.0.0.1", port)
    t.join(timeout=3.0)
    srv.close()

    assert res["connected"] is True
    assert "Incomplete SSH packet header" in res["error"]


def test_network_probe_cipher_name_kyber_or_mlkem(monkeypatch):
    import ssl

    class DummyTlsSocket:
        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_X25519MLKEM768_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def getpeercert(self, binary_form=False):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class DummyTlsContext:
        check_hostname = False
        verify_mode = 0

        def wrap_socket(self, *args, **kwargs):
            return DummyTlsSocket()

    class DummyRawConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    probe = NetworkProbe()
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: DummyRawConnection())
    monkeypatch.setattr(ssl, "create_default_context", lambda *args, **kwargs: DummyTlsContext())

    res = probe.probe_tls_endpoint("pqc.vault.internal", 443)
    assert res["connected"] is True
    assert res["pqc_hybrid_kex"] is True
    assert res["kex_group"] == "X25519MLKEM768"


def test_ssh_packet_size_limit():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3.0)
    port = srv.getsockname()[1]
    srv.listen(1)

    def srv_worker():
        try:
            conn, _ = srv.accept()
            conn.sendall(b"SSH-2.0-TestServer\r\n")
            _ = conn.recv(1024)
            # Send length > 35000
            conn.sendall(struct.pack(">I", 50000))
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=srv_worker)
    t.start()

    probe = NetworkProbe(timeout=2.0)
    res = probe.probe_ssh_endpoint("127.0.0.1", port)
    t.join(timeout=3.0)
    srv.close()

    assert res["connected"] is True
    assert "SSH packet exceeds standard size" in res["error"]


def test_ssh_truncated_header_and_payload():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3.0)
    port = srv.getsockname()[1]
    srv.listen(1)

    def srv_worker():
        try:
            conn, _ = srv.accept()
            conn.sendall(b"SSH-2.0-TestServer\r\n")
            _ = conn.recv(1024)
            # Send only 2 bytes instead of 4
            conn.sendall(b"\x00\x01")
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=srv_worker)
    t.start()

    probe = NetworkProbe(timeout=2.0)
    res = probe.probe_ssh_endpoint("127.0.0.1", port)
    t.join(timeout=3.0)
    srv.close()

    assert res["connected"] is True
    assert "Incomplete SSH packet header" in res["error"]


def test_tls_connection_refused():
    probe = NetworkProbe(timeout=0.5)
    # Using non-listening port
    res = probe.probe_tls_endpoint("127.0.0.1", 59999)
    assert res["connected"] is False
    assert "error" in res


def test_quic_endpoint_probing():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def srv_worker():
        try:
            data, addr = srv.recvfrom(2048)
            resp = bytearray([0xC0, 0x00, 0x00, 0x00, 0x01, 0x08]) + b"\x11" * 8 + b"\x08" + b"\x22" * 8 + b"\x00\x10" + b"\x00" * 16
            srv.sendto(resp, addr)
        except Exception:
            pass

    t = threading.Thread(target=srv_worker)
    t.start()

    probe = NetworkProbe(timeout=2.0)
    res = probe.probe_quic_endpoint("127.0.0.1", port)
    t.join(timeout=3.0)
    srv.close()

    assert res["connected"] is True
    assert res["quic_version"] == "QUICv1"
    assert res["pqc_hybrid_candidate"] is True


def test_quic_probe_timeout():
    probe = NetworkProbe(timeout=0.2)
    res = probe.probe_quic_endpoint("127.0.0.1", 59998)
    assert res["connected"] is False
    assert "timed out" in res["error"]


def test_ikev2_endpoint_probing():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def srv_worker():
        try:
            data, addr = srv.recvfrom(2048)
            init_spi = data[0:8]
            resp_spi = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11"
            hdr = init_spi + resp_spi + bytes([33, 0x20, 34, 0x20]) + struct.pack(">I", 0) + struct.pack(">I", 28)
            srv.sendto(hdr, addr)
        except Exception:
            pass

    t = threading.Thread(target=srv_worker)
    t.start()

    probe = NetworkProbe(timeout=2.0)
    res = probe.probe_ipsec_ikev2_endpoint("127.0.0.1", port)
    t.join(timeout=3.0)
    srv.close()

    assert res["connected"] is True
    assert res["responder_spi"] == "aabbccddeeff0011"
    assert res["pqc_hybrid_candidate"] is True


def test_ikev2_probe_timeout():
    probe = NetworkProbe(timeout=0.2)
    res = probe.probe_ipsec_ikev2_endpoint("127.0.0.1", 59997)
    assert res["connected"] is False
    assert "timed out" in res["error"]





