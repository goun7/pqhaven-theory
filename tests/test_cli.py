"""Tests for pqscan CLI commands using Click CliRunner."""

from click.testing import CliRunner
from pqhaven import __version__
from pqhaven.cli import main


def test_cli_version():
    """A1c-2026-10-22: hardcoded 2.0.0 yerine __version__ ile olculur.

    Bu-test-de-cift-kaynak-kusurunun-bir-yansimasiydı ( pin'siz-sovet-2.0.0
    yaziyordu). Surum-yukselince-bu-test-stale-oluyordu; artik-kaynaktan
    geldigi-icin-elle-bakim-gerekmez."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_scan_dir_command(tmp_path):
    (tmp_path / "app.py").write_text("import RSA\n", encoding="utf-8")
    runner = CliRunner()
    cbom_out = tmp_path / "out_cbom.json"
    html_out = tmp_path / "out_cockpit.html"

    result = runner.invoke(main, [
        "scan-dir",
        str(tmp_path),
        "--output-cbom", str(cbom_out),
        "--html", str(html_out)
    ])
    assert result.exit_code == 0
    assert cbom_out.exists()
    assert html_out.exists()


def test_cli_scan_network_fallback(tmp_path):
    runner = CliRunner()
    cbom_out = tmp_path / "net_cbom.json"
    html_out = tmp_path / "net_cockpit.html"

    # 1. With --demo flag, it produces clean reference output
    result = runner.invoke(main, [
        "scan",
        "127.0.0.1:54321",
        "--demo",
        "--output-cbom", str(cbom_out),
        "--html", str(html_out)
    ])
    assert result.exit_code == 0
    assert cbom_out.exists()
    assert html_out.exists()

    # 2. Without --demo flag and unreachable host, it fails cleanly with non-zero exit code
    fail_res = runner.invoke(main, [
        "scan",
        "127.0.0.1:54321",
    ])
    assert fail_res.exit_code != 0
    assert "Hedefe bağlanılamadı" in fail_res.output or "Error" in fail_res.output


def test_cli_ssh_command(tmp_path):
    runner = CliRunner()
    cbom_out = tmp_path / "ssh_cbom.json"
    html_out = tmp_path / "ssh_cockpit.html"

    # 1. With --demo flag, it produces clean reference output
    result = runner.invoke(main, [
        "ssh",
        "127.0.0.1",
        "-p", "54322",
        "--demo",
        "--output-cbom", str(cbom_out),
        "--html", str(html_out)
    ])
    assert result.exit_code == 0
    assert cbom_out.exists()
    assert html_out.exists()

    # 2. Without --demo flag and unreachable host, it fails cleanly
    fail_res = runner.invoke(main, [
        "ssh",
        "127.0.0.1",
        "-p", "54322",
    ])
    assert fail_res.exit_code != 0
    assert "SSH bağlantısı kurulamadı" in fail_res.output or "Error" in fail_res.output


def test_cli_scan_connected_endpoint(tmp_path):
    import socket
    import ssl
    import threading
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

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
    srv.listen(4)

    def srv_worker():
        # DALGA-D10: CLI artik TLS el sikismasindan sonra bir de ham
        # TLS1.3 0x11ec probe'u yapar. 2. baglantiyi kabul etmezsek
        # probe RST yer ve PQRI N/A (fail-loud) olurdu.
        for _ in range(2):
            try:
                raw_conn, _ = srv.accept()
                with ssl_ctx.wrap_socket(raw_conn, server_side=True) as sconn:
                    try:
                        sconn.recv(2048)
                    except Exception:
                        pass
            except Exception:
                pass

    t = threading.Thread(target=srv_worker)
    t.start()

    runner = CliRunner()
    result = runner.invoke(main, [
        "scan",
        f"127.0.0.1:{port}",
        "-p", str(port),
        "--shelf-life", "5",
        "--migration-time", "3",
    ])
    t.join(timeout=3.0)
    srv.close()

    assert result.exit_code == 0
    assert "PQRI Risk Skoru" in result.output


def test_cli_ssh_connected_endpoint(tmp_path):
    import socket
    import struct
    import threading

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3.0)
    port = srv.getsockname()[1]
    srv.listen(1)

    def srv_worker():
        conn, _ = srv.accept()
        conn.sendall(b"SSH-2.0-OpenSSH_9.8p1\r\n")
        _ = conn.recv(1024)
        cookie = b"\x00" * 16
        kex_str = b"mlkem768x25519-sha512@openssh.com"
        hk_str = b"ssh-rsa"
        ciphers = b"aes256-gcm@openssh.com"
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

    runner = CliRunner()
    result = runner.invoke(main, [
        "ssh",
        "127.0.0.1",
        "-p", str(port),
    ])
    t.join()
    srv.close()

    assert result.exit_code == 0
    assert "mlkem768x25519" in result.output or "PQRI Risk Skoru" in result.output


def test_cli_serve_command(monkeypatch, tmp_path):
    import socketserver
    import webbrowser

    monkeypatch.setattr(webbrowser, "open", lambda url: True)

    class DummyServer:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def serve_forever(self):
            raise KeyboardInterrupt()

    monkeypatch.setattr(socketserver, "TCPServer", DummyServer)

    runner = CliRunner()
    result = runner.invoke(main, [
        "serve",
        "--target", "portal.internal",
        "--port", "8443",
        "--open-browser"
    ])

    assert result.exit_code == 0
    assert "PQHaven Telemetry Cockpit Canlı" in result.output

    # Test serve with --cbom file
    dummy_cbom = tmp_path / "cbom_sample.json"
    dummy_cbom.write_text('{"bomFormat":"CycloneDX","components":[{"name":"k1","cryptoProperties":{"algorithmName":"ML-KEM-768","assetType":"algorithm"}}]}', encoding="utf-8")
    result_cbom = runner.invoke(main, [
        "serve",
        "--cbom", str(dummy_cbom),
        "--port", "8444",
        "--open-browser"
    ])
    assert result_cbom.exit_code == 0


def test_cli_simulate_command():
    runner = CliRunner()
    result = runner.invoke(main, [
        "simulate",
        "-n", "500",
        "-x", "8.0",
        "--migration-min", "2.0",
        "--migration-max", "5.0",
    ])
    assert result.exit_code == 0
    assert "Mosca Eşitsizliği Monte Carlo Q-Day Simülatörü" in result.output
    assert "HNDL Zafiyet Riski" in result.output
    assert "Histogramı" in result.output


def test_cli_attest_command(tmp_path):
    runner = CliRunner()
    vc_out = tmp_path / "vc.json"
    result = runner.invoke(main, [
        "attest",
        "https://api.vault.internal",
        "--demo",
        "-o", str(vc_out)
    ])
    assert result.exit_code == 0
    assert "Kriptografik Tasdik Başarıyla Üretildi" in result.output
    assert "CBOM Merkle Root" in result.output
    assert vc_out.exists()
    assert "VerifiableCredential" in vc_out.read_text(encoding="utf-8")


def test_cli_scan_csv_export(tmp_path):
    runner = CliRunner()
    csv_out = tmp_path / "assets.csv"
    result = runner.invoke(main, [
        "scan",
        "127.0.0.1:54323",
        "--demo",
        "--output-csv", str(csv_out)
    ])
    assert result.exit_code == 0
    assert csv_out.exists()
    assert "RecommendedReplacement" in csv_out.read_text(encoding="utf-8")


def test_cli_ssh_and_scandir_csv_export(tmp_path):
    runner = CliRunner()
    csv_ssh = tmp_path / "ssh_assets.csv"
    res1 = runner.invoke(main, [
        "ssh",
        "127.0.0.1",
        "-p", "54329",
        "--demo",
        "--output-csv", str(csv_ssh)
    ])
    assert res1.exit_code == 0
    assert csv_ssh.exists()

    (tmp_path / "sample.py").write_text("import RSA\n", encoding="utf-8")
    csv_dir = tmp_path / "dir_assets.csv"
    res2 = runner.invoke(main, [
        "scan-dir",
        str(tmp_path),
        "--output-csv", str(csv_dir)
    ])
    assert res2.exit_code == 0
    assert csv_dir.exists()


def test_cli_scandir_more_than_15_assets(tmp_path):
    for i in range(20):
        (tmp_path / f"test_{i}.py").write_text(f"# finding {i}\nkey = RSA.generate(2048)\n", encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(main, ["scan-dir", str(tmp_path)])
    assert res.exit_code == 0
    assert "ve" in res.output and "varlık daha" in res.output


def test_cli_attest_connected_endpoint(tmp_path):
    import socket
    import ssl
    import threading
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

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

    runner = CliRunner()
    res = runner.invoke(main, ["attest", f"https://127.0.0.1:{port}"])
    t.join(timeout=3.0)
    srv.close()

    assert res.exit_code == 0
    assert "Kriptografik Tasdik Başarıyla Üretildi" in res.output


def test_cli_export_issues_github_and_jira(tmp_path):
    from pqhaven.engine import PQScanEngine
    engine = PQScanEngine()
    assets = [
        {"name": "auth-key", "algorithm": "RSA-2048", "type": "key", "key_size": 2048},
        {"name": "kem-exchange", "algorithm": "ML-KEM-768", "type": "protocol", "key_size": 768},
    ]
    report = engine.assess_target("test.export", assets)
    cbom_json = tmp_path / "cbom.json"
    cbom_json.write_text(report.cbom.model_dump_json(by_alias=True), encoding="utf-8")

    out_gh = tmp_path / "github_issues.json"
    out_jira = tmp_path / "jira_tickets.json"

    runner = CliRunner()
    res_gh = runner.invoke(main, [
        "export-issues",
        "--cbom", str(cbom_json),
        "--format", "github",
        "--output", str(out_gh),
    ])
    assert res_gh.exit_code == 0
    assert "GITHUB bileti başarıyla oluşturuldu" in res_gh.output
    assert out_gh.exists()

    res_jira = runner.invoke(main, [
        "export-issues",
        "--cbom", str(cbom_json),
        "--format", "jira",
        "--output", str(out_jira),
    ])
    assert res_jira.exit_code == 0
    assert "JIRA bileti başarıyla oluşturuldu" in res_jira.output
    assert out_jira.exists()


def test_cli_report_command(tmp_path):
    from pqhaven.engine import PQScanEngine
    engine = PQScanEngine()
    assets = [
        {"name": "tls-leaf", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048},
        {"name": "ssh-kex", "algorithm": "ML-KEM-768", "type": "protocol", "key_size": 768},
    ]
    report_obj = engine.assess_target("report-test", assets)
    cbom_file = tmp_path / "cbom_source.json"
    cbom_file.write_text(report_obj.cbom.model_dump_json(by_alias=True), encoding="utf-8")

    out_html = tmp_path / "report.html"
    out_csv = tmp_path / "report.csv"
    out_json = tmp_path / "report.json"

    runner = CliRunner()
    res = runner.invoke(main, [
        "report",
        "--cbom", str(cbom_file),
        "--output-html", str(out_html),
        "--output-csv", str(out_csv),
        "--output-json", str(out_json),
    ])
    assert res.exit_code == 0
    assert "Executive Cockpit kaydedildi" in res.output
    assert "Envanter CSV kaydedildi" in res.output
    assert "Rapor JSON kaydedildi" in res.output
    assert out_html.exists()
    assert out_csv.exists()
    assert out_json.exists()


def test_cli_scan_network_and_path_combination(tmp_path):
    (tmp_path / "key.pem").write_text("dummy key data", encoding="utf-8")
    runner = CliRunner()
    cbom_out = tmp_path / "combo_cbom.json"
    html_out = tmp_path / "combo_cockpit.html"

    # 1. Scan with --network (including port 22) and --path and --demo
    res = runner.invoke(main, [
        "scan",
        "--network", "127.0.0.1:443,127.0.0.1:22",
        "--path", str(tmp_path),
        "--demo",
        "--output-cbom", str(cbom_out),
        "--output-html", str(html_out),
    ])
    assert res.exit_code == 0
    assert cbom_out.exists()
    assert html_out.exists()

    # 2. Scan without target, network, or path raises ClickException
    fail_res = runner.invoke(main, ["scan"])
    assert fail_res.exit_code != 0
    assert "Lütfen bir hedef belirtin" in fail_res.output


def test_cli_simulate_with_seed_crqc_year_and_output_json(tmp_path):
    sim_out = tmp_path / "sim_results.json"
    runner = CliRunner()
    res = runner.invoke(main, [
        "simulate",
        "-n", "500",
        "--seed", "42",
        "--crqc-year", "2033.0",
        "--output-json", str(sim_out),
    ])
    assert res.exit_code == 0
    assert "Seed: 42" in res.output
    assert "Mosca Eşitsizliği Monte Carlo Q-Day Simülatörü" in res.output
    assert sim_out.exists()
    assert "vulnerability_probability" in sim_out.read_text(encoding="utf-8")


def test_cli_attest_with_cbom_and_contract_params(tmp_path):
    from pqhaven.engine import PQScanEngine
    engine = PQScanEngine()
    assets = [
        {"name": "tls-leaf", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048},
        {"name": "sig-algo", "algorithm": "ML-DSA-65", "type": "algorithm", "key_size": 192},
    ]
    report_obj = engine.assess_target("attest-cbom-test", assets)
    cbom_file = tmp_path / "cbom_attest.json"
    cbom_file.write_text(report_obj.cbom.model_dump_json(by_alias=True), encoding="utf-8")

    vc_out = tmp_path / "attestation_vc.jsonld"
    runner = CliRunner()

    # 1. Attest using --cbom and --contract-params
    res = runner.invoke(main, [
        "attest",
        "--cbom", str(cbom_file),
        "--issuer-did", "did:pqh:kurum-auditor",
        "--contract-params",
        "--output-vc", str(vc_out),
    ])
    assert res.exit_code == 0
    assert "EVM On-Chain Kontrat Parametreleri" in res.output
    assert "PQHavenRegistry.registerAssessment" in res.output
    assert "entityId" in res.output
    assert "cbomMerkleRoot" in res.output
    assert "did:pqh:kurum-auditor" in res.output
    assert vc_out.exists()

    # 2. Attest without target or cbom fails cleanly
    fail_res = runner.invoke(main, ["attest"])
    assert fail_res.exit_code != 0
    assert "Lütfen bir hedef belirtin veya '--cbom' dosyası sağlayın" in fail_res.output








# --- DALGA-C-2: gatekeep --install-hook fail-closed pin'leri (PQH-CLI-1) ---

def test_gatekeep_install_hook_readonly_fs_fail_closed(tmp_path, monkeypatch):
    """PQH-CLI-1 (DALGA-C-2-DUZELTILDI): chmod başarısız olursa '✅ kuruldu'
    yerine ClickException ( rc=1) fırlatmalı — güvenlik-kapısı kapalıyken
    yeşil-ışık YOK."""
    import pathlib
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    runner = CliRunner()
    orig_chmod = pathlib.Path.chmod

    def _chmod_kir(self, mode):
        raise OSError("read-only-file-system (simule)")

    monkeypatch.setattr(pathlib.Path, "chmod", _chmod_kir)
    res = runner.invoke(main, ["gatekeep", "--path", str(repo), "--install-hook"])
    monkeypatch.undo()
    assert res.exit_code != 0
    assert "kullanılamadı" in res.output or "chmod" in res.output
    # kanca-yazıldı-ama-Calıstırılabilir-degil → fail-closed
    assert "✅ Git pre-commit kancası kuruldu" not in res.output


def test_gatekeep_install_hook_basarili(tmp_path):
    """PQH-CLI-1 pozitif-yol: okunabilir-FS'te kanca-yukleme rc=0 + calisabilir."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    runner = CliRunner()
    res = runner.invoke(main, ["gatekeep", "--path", str(repo), "--install-hook"])
    assert res.exit_code == 0
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    assert hook.stat().st_mode & 0o111, "kanca calistirilabilir degil"
    assert "✅ Git pre-commit kancası kuruldu" in res.output
