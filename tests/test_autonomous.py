"""Tests for Autonomous Zero-Touch Engine (Gatekeeper, Pre-Commit, Sentinel, Remediator)."""

import json
from pathlib import Path
from click.testing import CliRunner
from pqhaven.cli import main
from pqhaven.daemon import SentinelDaemon
from pqhaven.remediator import CodeRemediator


def test_install_git_pre_commit_hook(tmp_path: Path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    runner = CliRunner()
    res = runner.invoke(main, ["gatekeep", "--path", str(tmp_path), "--install-hook"])
    assert res.exit_code == 0
    assert "Git pre-commit kancası kuruldu" in res.output

    hook_file = git_dir / "hooks" / "pre-commit"
    assert hook_file.is_file()
    content = hook_file.read_text(encoding="utf-8")
    assert "pqscan gatekeep" in content


def test_gatekeeper_blocks_shor_vulnerable_code(tmp_path: Path):
    bad_py = tmp_path / "bad.py"
    bad_py.write_text("import RSA\nkey = RSA.generate(2048)\n", encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(main, ["gatekeep", "--path", str(tmp_path), "--fail-on-shor"])
    assert res.exit_code == 1
    assert "GİT COMMIT / DERLEME REDDEDİLDİ" in res.output


def test_gatekeeper_passes_safe_code(tmp_path: Path):
    safe_py = tmp_path / "safe.py"
    safe_py.write_text("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n", encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(main, ["gatekeep", "--path", str(tmp_path), "--fail-on-shor"])
    assert res.exit_code == 0
    assert "Kapı Bekçisi Geçildi" in res.output


def test_sentinel_daemon_detect_drift_and_webhook(tmp_path: Path, monkeypatch):
    import urllib.request

    sentinel = SentinelDaemon(interval_seconds=10, max_pqri_threshold=50.0)

    # State 1
    state1 = {
        "timestamp": 1000.0,
        "pqri_score": 20.0,
        "overall_grade": "READY",
        "assets": {"asset1": ("ML-KEM-768", False)},
    }

    # State 2 with newly added Shor-vulnerable RSA key
    state2 = {
        "timestamp": 2000.0,
        "pqri_score": 75.0,
        "overall_grade": "CRITICAL",
        "assets": {
            "asset1": ("ML-KEM-768", False),
            "asset2": ("RSA-2048", True),
        },
    }

    drift = sentinel.detect_drift(state1, state2)
    assert drift["has_drift"] is True
    assert len(drift["new_vulnerabilities"]) == 1
    assert "asset2 (RSA-2048)" in drift["new_vulnerabilities"][0]
    assert drift["score_delta"] == 55.0

    # Real local HTTP server for webhook dispatch
    import http.server
    import threading

    received_payload: dict = {}

    class WebhookHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            received_payload.update(json.loads(body.decode("utf-8")))
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), WebhookHandler)
    server_port = server.server_port
    t = threading.Thread(target=server.handle_request)
    t.start()

    ok = sentinel.dispatch_alert(f"http://127.0.0.1:{server_port}/webhook", drift, state2)
    t.join(timeout=3.0)
    server.server_close()

    assert ok is True
    assert received_payload.get("event") == "PQHaven.CryptographicDriftDetected"
    assert received_payload.get("pqriScore") == 75.0
    assert received_payload.get("alertLevel") == "CRITICAL"


def test_sentinel_daemon_run_loop_max_cycles(tmp_path: Path):
    d = SentinelDaemon(interval_seconds=0)
    history = d.run_loop(targets=[], paths=[str(tmp_path)], max_cycles=1)
    assert len(history) == 1
    assert "state" in history[0]
    assert "drift" in history[0]


def test_code_remediator_patch_generation_and_apply(tmp_path: Path):
    remediator = CodeRemediator()
    vulnerable_py = tmp_path / "legacy_app.py"
    original_code = (
        "from cryptography.hazmat.primitives import hashes\n"
        "digest1 = hashes.SHA1()\n"
        "digest2 = hashes.MD5()\n"
    )
    vulnerable_py.write_text(original_code, encoding="utf-8")

    # 1. Generate patch
    patch = remediator.generate_patch(vulnerable_py)
    assert patch is not None
    assert "-digest1 = hashes.SHA1()" in patch
    assert "+digest1 = hashes.SHA256()" in patch
    assert "-digest2 = hashes.MD5()" in patch
    assert "+digest2 = hashes.SHA256()" in patch

    # 2. Scan and apply
    results = remediator.scan_and_remediate(tmp_path, apply=True)
    assert len(results) == 1
    assert results[0]["applied"] is True

    # 3. Verify backup and modified file
    bak_file = tmp_path / "legacy_app.py.bak"
    assert bak_file.is_file()
    assert "SHA1" in bak_file.read_text(encoding="utf-8")

    new_content = vulnerable_py.read_text(encoding="utf-8")
    assert "hashes.SHA256()" in new_content
    assert "SHA1" not in new_content
    assert "MD5" not in new_content


def test_cli_auto_discover_command(tmp_path: Path):
    cbom_file = tmp_path / "auto_discovered_cbom.json"
    runner = CliRunner()
    res = runner.invoke(main, ["auto-discover", "--output-cbom", str(cbom_file)])
    assert res.exit_code == 0
    assert "kriptografik varlık otonom keşfedildi" in res.output
    assert cbom_file.is_file()


def test_cli_fix_command(tmp_path: Path):
    code_file = tmp_path / "app.py"
    code_file.write_text("import hashes\nh = hashes.SHA1()\n", encoding="utf-8")
    patch_out = tmp_path / "diff.patch"

    runner = CliRunner()
    res = runner.invoke(main, ["fix", "--path", str(tmp_path), "--output-patch", str(patch_out)])
    assert res.exit_code == 0
    assert "kriptografik iyileştirme tespit edildi" in res.output
    assert patch_out.is_file()


def test_remediator_edge_cases_and_clean_file(tmp_path: Path):
    remediator = CodeRemediator()
    non_existent = tmp_path / "does_not_exist.py"
    assert remediator.generate_patch(non_existent) is None
    assert remediator.apply_file(non_existent) is False

    clean_file = tmp_path / "clean.py"
    clean_file.write_text("x = 42\n", encoding="utf-8")
    assert remediator.generate_patch(clean_file) is None
    assert remediator.apply_file(clean_file) is False

    des_file = tmp_path / "legacy_des.java"
    des_file.write_text('Cipher c = Cipher.getInstance("DES");\n', encoding="utf-8")
    patch = remediator.generate_patch(des_file)
    assert patch is not None
    assert "AES/GCM/NoPadding" in patch


def test_sentinel_daemon_scan_cycle_and_cli(tmp_path: Path):
    import socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    daemon = SentinelDaemon()
    cycle = daemon.scan_cycle(targets=[f"127.0.0.1:{port}"], paths=[str(tmp_path)])
    srv.close()
    assert "timestamp" in cycle
    assert "pqri_score" in cycle

    runner = CliRunner()
    res = runner.invoke(main, ["daemon", "--path", str(tmp_path), "--max-cycles", "1"])
    assert res.exit_code == 0
    assert "PQHaven Sentinel Daemon Başlatıldı" in res.output



