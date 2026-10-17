"""Autonomous Continuous Sentinel Daemon for Cryptographic Drift & Webhook Alerts.

Runs 24/7 in background (container / daemon / systemd service):
1. Periodically probes network endpoints and scans repository paths.
2. Computes state deltas (cryptographic drift: newly added Shor-vulnerable assets, expiring certs).
3. Dispatches automated JSON alert payloads to Slack, Microsoft Teams, or SIEM webhooks.
"""

from __future__ import annotations
import json
import logging
import time
import urllib.request
from typing import Any, Dict, List, Optional
from pqhaven.engine import PQScanEngine
from pqhaven.network import NetworkProbe
from pqhaven.scanner import LocalScanner

logger = logging.getLogger(__name__)


class SentinelDaemon:
    """Continuous background cryptographic monitoring daemon."""

    def __init__(
        self,
        interval_seconds: int = 3600,
        webhook_url: Optional[str] = None,
        max_pqri_threshold: float = 40.0,
    ):
        self.interval = interval_seconds
        self.webhook_url = webhook_url
        self.threshold = max_pqri_threshold
        self.engine = PQScanEngine()
        self.network_probe = NetworkProbe(timeout=3.0)
        self.local_scanner = LocalScanner()
        self.last_state: Dict[str, Any] = {}

    def scan_cycle(self, targets: List[str], paths: List[str]) -> Dict[str, Any]:
        """Executes a single autonomous audit cycle across network endpoints and paths."""
        discovered_assets: List[Dict[str, Any]] = []
        # DALGA-D10 (PQH-NET-2): kanit-toplama kalitesi - hic hedefe
        # baglanilamadiysa PQRI N/A olur (fail-loud; eskiden 0.0/READY).
        probe_health: Dict[str, int] = {"total": 0, "connected": 0, "probe_errors": 0}

        # 1. Network Endpoint Discovery
        for target in targets:
            if ":" in target:
                host, port_str = target.split(":", 1)
                port = int(port_str)
            else:
                host, port = target, 443

            probe_health["total"] += 1
            tls_res = self.network_probe.probe_tls_endpoint(host, port)
            if tls_res.get("connected"):
                probe_health["connected"] += 1
                if tls_res.get("probe_error"):
                    probe_health["probe_errors"] += 1
                discovered_assets.append({
                    "name": f"{host}:{port}-tls-protocol",
                    "algorithm": tls_res.get("kex_group", "ECDH-X25519"),
                    "type": "protocol",
                    "key_size": 768 if tls_res.get("pqc_hybrid_kex") else 256,
                })
                for cert in tls_res.get("certificates", []):
                    discovered_assets.append({
                        "name": f"{host}:{port}-cert ({cert['subject_cn']})",
                        "algorithm": cert["algorithm"],
                        "type": "certificate",
                        "key_size": cert["key_size"],
                    })

        # 2. Local Filesystem Discovery
        for p in paths:
            assets = self.local_scanner.scan_directory(p)
            discovered_assets.extend(assets)

        report = self.engine.assess_target(
            "autonomous-sentinel", discovered_assets, probe_health=probe_health
        )
        current_state = {
            "timestamp": time.time(),
            "pqri_score": report.pqri_score,
            "overall_grade": report.overall_grade.value,
            "asset_count": len(report.cbom.components),
            "hndl_count": report.hndl_vulnerability_count,
            "assets": {c.name: (c.crypto_properties.algorithm_name, c.crypto_properties.shor_vulnerable) for c in report.cbom.components},
            "report": report,
        }
        return current_state

    def detect_drift(self, prev: Dict[str, Any], curr: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates cryptographic state drift and new vulnerabilities between cycles."""
        if not prev:
            return {
                "has_drift": False,
                "new_vulnerabilities": [],
                "score_delta": 0.0,
                "new_assets": list(curr.get("assets", {}).keys()),
            }

        prev_assets = prev.get("assets", {})
        curr_assets = curr.get("assets", {})

        new_vulns: List[str] = []
        for name, (algo, is_shor) in curr_assets.items():
            if name not in prev_assets and is_shor:
                new_vulns.append(f"{name} ({algo})")

        # DALGA-D10 (PQH-NET-2): N/A (None) skoru sayiyla cikalamaz -
        # TypeError yerine N/A'ya gecis/kaybolus drift olarak tetiklenir.
        prev_score = prev.get("pqri_score")
        curr_score = curr.get("pqri_score")
        if prev_score is None or curr_score is None:
            if (prev_score is None) != (curr_score is None):
                has_drift = True
                score_delta = 0.0 if curr_score is None else -1000.0
            else:
                has_drift = len(new_vulns) > 0  # ikisi de N/A: sadece yeni vuln drift
                score_delta = 0.0
        else:
            score_delta = round(curr_score - prev_score, 2)
            has_drift = len(new_vulns) > 0 or abs(score_delta) > 5.0

        return {
            "has_drift": has_drift,
            "new_vulnerabilities": new_vulns,
            "score_delta": score_delta,
            "new_assets": [n for n in curr_assets if n not in prev_assets],
        }

    def dispatch_alert(self, webhook_url: str, drift: Dict[str, Any], state: Dict[str, Any]) -> bool:
        """Sends an autonomous HTTP POST JSON alert to configured SIEM/Slack webhook."""
        payload = {
            "event": "PQHaven.CryptographicDriftDetected",
            "source": "SentinelDaemon",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(state["timestamp"])),
            "pqriScore": state["pqri_score"],
            "grade": state["overall_grade"],
            "drift": {
                "scoreDelta": drift["score_delta"],
                "newVulnerabilitiesCount": len(drift["new_vulnerabilities"]),
                "newVulnerabilities": drift["new_vulnerabilities"],
            },
            # DALGA-D10 (PQH-NET-2): None (N/A) >= threshold kiyaslamasi
            # TypeError firlatir - N/A her zaman CRITICAL seviyesinde uyar.
            "alertLevel": "CRITICAL" if (state["pqri_score"] is None or state["pqri_score"] >= self.threshold) else "INFO",
        }

        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "PQHaven-Sentinel/2.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status in (200, 201, 202, 204)
        except Exception as exc:
            logger.error("Failed to dispatch sentinel webhook alert: %s", exc)
            return False

    def run_loop(
        self,
        targets: List[str],
        paths: List[str],
        max_cycles: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Runs the autonomous daemon loop with interval sleeps."""
        cycles_completed = 0
        history: List[Dict[str, Any]] = []

        while True:
            curr_state = self.scan_cycle(targets, paths)
            drift = self.detect_drift(self.last_state, curr_state)

            if drift["has_drift"] and self.webhook_url:
                self.dispatch_alert(self.webhook_url, drift, curr_state)

            self.last_state = curr_state
            history.append({"state": curr_state, "drift": drift})
            cycles_completed += 1

            if max_cycles and cycles_completed >= max_cycles:
                break

            time.sleep(self.interval)

        return history
