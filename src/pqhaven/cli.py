"""PQHaven CLI Interface (pqscan).

Command-line tool for:
1. Live network TLS & SSH cryptographic discovery.
2. Local repository, keystore, and code scanning.
3. CycloneDX 1.6 CBOM generation and validation.
4. Monte Carlo Q-Day stochastic stress simulation (`pqscan simulate`).
5. Cryptographic Attestation & On-Chain Registry Payload (`pqscan attest`).
6. Executive Cockpit HTML report generation and local telemetry serving.
"""

from __future__ import annotations
import hashlib
import http.server
import json
import os
import socket
import socketserver
import sys
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from pqhaven.cockpit import generate_cockpit_html
from pqhaven.engine import PQScanEngine
from pqhaven.network import NetworkProbe
from pqhaven.scanner import LocalScanner

console = Console()


@click.group()
@click.version_option(version="2.0.0", prog_name="pqscan")
def main():
    """🛡️ PQHaven: Post-Quantum Discovery, CBOM & Crypto-Agility Engine."""
    pass


@main.command(name="scan")
@click.argument("target", required=False)
@click.option("--network", "-n", help="Comma-separated network endpoints (e.g., api.kurum.gov.tr:443,vpn.kurum.gov.tr:22)")
@click.option("--path", type=click.Path(exists=True), help="Local codebase or directory to scan")
@click.option("--port", "-p", default=443, help="Default target network port (default: 443)")
@click.option("--shelf-life", "-x", default=10.0, help="Data shelf-life in years (Mosca X)")
@click.option("--migration-time", "-y", default=3.0, help="Migration time in years (Mosca Y)")
@click.option("--crqc-arrival", "-z", default=7.5, help="Years to CRQC arrival (Mosca Z)")
@click.option("--demo", is_flag=True, default=False, help="Run with offline reference architecture data")
@click.option("--output-cbom", "-o", type=click.Path(), help="Export CycloneDX 1.6 CBOM to JSON")
@click.option("--output-csv", type=click.Path(), help="Export assets to CSV")
@click.option("--output-html", type=click.Path(), help="Export Executive Cockpit to HTML file")
@click.option("--html", type=click.Path(), help="Export Executive Cockpit to HTML file (alias)")
def scan(
    target: str | None,
    network: str | None,
    path: str | None,
    port: int,
    shelf_life: float,
    migration_time: float,
    crqc_arrival: float,
    demo: bool,
    output_cbom: str | None,
    output_csv: str | None,
    output_html: str | None,
    html: str | None,
):
    """Probe network endpoint or local directory for TLS/SSH cryptographic assets and CBOM."""
    if not target and not network and not path:
        raise click.ClickException("Lütfen bir hedef belirtin: 'target' argümanı, '--network' veya '--path' parametrelerinden en az biri gereklidir.")

    endpoints: List[str] = []
    if target:
        endpoints.append(target)
    if network:
        for ep in network.split(","):
            ep_s = ep.strip()
            if ep_s and ep_s not in endpoints:
                endpoints.append(ep_s)

    assets: List[Dict[str, Any]] = []
    primary_target_name = target or network or path or "system"
    # DALGA-D10 (PQH-NET-2): kanit-toplama kalitesini olc - hic hedefe
    # baglanilamadiysa PQRI N/A olur (fail-loud, eskiden 0.0/READY).
    probe_health: Dict[str, int] = {"total": 0, "connected": 0, "probe_errors": 0}

    # Network scanning
    if endpoints:
        for ep in endpoints:
            target_raw = ep.replace("https://", "").replace("http://", "").replace("ssh://", "").split("/")[0]
            ep_port = port
            if ":" in target_raw:
                clean_host, port_str = target_raw.split(":", 1)
                if port_str.isdigit():
                    ep_port = int(port_str)
            else:
                clean_host = target_raw

            console.print(Panel.fit(
                f"[bold cyan]PQHaven Active Network Probe[/bold cyan]\n"
                f"Hedef: [bold white]{clean_host}:{ep_port}[/bold white] · Standart: [green]CycloneDX 1.6 CBOM[/green]",
                border_style="cyan"
            ))

            if demo:
                console.print("[bold yellow]ℹ️ Çevrimdışı referans demo modu devrede.[/bold yellow]")
                assets.extend([
                    {"name": f"{clean_host}-reference-rsa", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048},
                    {"name": f"{clean_host}-reference-kex", "algorithm": "ECDH-X25519", "type": "protocol", "key_size": 256},
                ])
            else:
                probe = NetworkProbe()
                probe_health["total"] += 1
                if ep_port == 22:
                    with Progress(SpinnerColumn(style="cyan"), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                        t_task = progress.add_task(f"[cyan]SSH_MSG_KEXINIT el sıkışması ({clean_host}:{ep_port})...[/cyan]", total=None)
                        probe_result = probe.probe_ssh_endpoint(clean_host, ep_port)
                        progress.update(t_task, completed=True)
                    if not probe_result["connected"]:
                        err_msg = probe_result.get("error") or "Bilinmeyen SSH soket hatası"
                        console.print(f"[bold red]❌ Ağ bağlantısı kurulamadı ({clean_host}:{ep_port} - {err_msg}).[/bold red]")
                        if len(endpoints) == 1 and not path:
                            raise click.ClickException(f"Hedefe bağlanılamadı: {err_msg}")
                        continue
                    probe_health["connected"] += 1
                    pqc_kex = probe_result.get("pqc_hybrid_kex", False)
                    assets.append({
                        "name": f"{clean_host}-ssh-kex",
                        "algorithm": "mlkem768x25519-sha512@openssh.com" if pqc_kex else "diffie-hellman-group14-sha256",
                        "type": "protocol",
                        "key_size": 768 if pqc_kex else 2048,
                    })
                    for hk in probe_result.get("host_key_algorithms", [])[:3]:
                        assets.append({
                            "name": f"{clean_host}-hostkey-{hk}",
                            "algorithm": "RSA-2048" if "rsa" in hk else "ECDSA-P256",
                            "type": "key",
                            "key_size": 2048 if "rsa" in hk else 256,
                        })
                else:
                    with Progress(SpinnerColumn(style="cyan"), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                        t_task = progress.add_task(f"[cyan]Canlı TLS el sıkışması yapılıyor ({clean_host}:{ep_port})...[/cyan]", total=None)
                        probe_result = probe.probe_tls_endpoint(clean_host, ep_port)
                        progress.update(t_task, completed=True)
                    if not probe_result["connected"]:
                        err_msg = probe_result.get("error") or "Bilinmeyen soket hatası"
                        console.print(f"[bold red]❌ Ağ bağlantısı kurulamadı ({clean_host}:{ep_port} - {err_msg}).[/bold red]")
                        if len(endpoints) == 1 and not path:
                            raise click.ClickException(f"Hedefe bağlanılamadı: {err_msg}")
                        continue
                    probe_health["connected"] += 1
                    if probe_result.get("probe_error"):
                        probe_health["probe_errors"] += 1

                    kex_name = probe_result.get("kex_group", "ECDH-X25519")
                    assets.append({
                        "name": f"{clean_host}-tls-protocol",
                        "algorithm": kex_name,
                        "type": "protocol",
                        "key_size": 768 if probe_result.get("pqc_hybrid_kex") else 256,
                    })
                    for cert in probe_result.get("certificates", []):
                        assets.append({
                            "name": f"{clean_host}-leaf-cert ({cert['subject_cn']})",
                            "algorithm": cert["algorithm"],
                            "type": "certificate",
                            "key_size": cert["key_size"],
                            "oid": cert.get("signature_algorithm"),
                        })

    # Local filesystem path scanning
    if path:
        console.print(f"[bold cyan]📂 Yerel dizin taranıyor:[/bold cyan] {path}")
        scanner = LocalScanner()
        local_assets = scanner.scan_directory(Path(path))
        console.print(f"[dim]Bulunan yerel kriptografik varlık sayısı: {len(local_assets)}[/dim]")
        assets.extend(local_assets)

    engine = PQScanEngine()
    report = engine.assess_target(
        target=primary_target_name,
        detected_assets=assets,
        shelf_life_years=shelf_life,
        migration_time_years=migration_time,
        crqc_arrival_years=crqc_arrival,
        probe_health=probe_health,
    )

    _render_report_table(report)

    # DALGA-D10 (PQH-NET-2) fail-loud: kanit-toplama tam-basarisizsa
    # (denendiginde hic hedefe baglanilamadi) rc!=0 ile biter - "0.0/READY"
    # raporu yalanci-yesil kapisi acik birakilamaz. Yerel --path taramasi
    # varsa (kanit mevcut) N/A'ya dusmez, sadece rc=0 ile uyarilir.
    if report.pqri_is_na and not path:
        # DALGA-D10: iki ayri N/A sebebi var - mesaj karistirmasin
        if probe_health["connected"] == 0:
            neden = "hicbir hedefe baglanilamadi (ag/DNS/timeout)"
        else:
            neden = f"baglanan {probe_health['connected']} hedeften ham-probe olcumu basarisiz ({report.none_reason})"
        raise click.ClickException(
            "PQRI olculemedi (N/A): " + neden
            + f" (denenen={probe_health['total']}, baglanan={probe_health['connected']}). "
            "Hedeflerin erisilebilir oldugundan emin olun veya teshis icin --demo / --path kullanin."
        )

    if output_cbom:
        with open(output_cbom, "w", encoding="utf-8") as f:
            f.write(report.cbom.model_dump_json(by_alias=True, indent=2))
        console.print(f"[bold green]✅ CycloneDX 1.6 CBOM kaydedildi:[/bold green] {output_cbom}")

    if output_csv:
        _export_csv(report, output_csv)
        console.print(f"[bold green]📊 Envanter CSV kaydedildi:[/bold green] {output_csv}")

    html_path = output_html or html
    if html_path:
        html_content = generate_cockpit_html(report)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[bold green]✨ Executive Cockpit kaydedildi:[/bold green] {html_path}")


@main.command(name="ssh")
@click.argument("target")
@click.option("--port", "-p", default=22, help="Target SSH port (default: 22)")
@click.option("--demo", is_flag=True, default=False, help="Run with offline SSH reference telemetry")
@click.option("--output-cbom", "-o", type=click.Path(), help="Export CycloneDX 1.6 CBOM to JSON")
@click.option("--output-csv", type=click.Path(), help="Export assets to CSV")
@click.option("--html", type=click.Path(), help="Export Executive Cockpit to HTML file")
def probe_ssh(target: str, port: int, demo: bool, output_cbom: str | None, output_csv: str | None, html: str | None):
    """Probe an SSH endpoint for RFC 4253 KEX algorithms and host keys."""
    clean_host = target.replace("ssh://", "").split("/")[0].split(":")[0]

    console.print(Panel.fit(
        f"[bold cyan]PQHaven Active SSH Transport Probe[/bold cyan]\n"
        f"Hedef: [bold white]{clean_host}:{port}[/bold white] · Protokol: [green]RFC 4253 KEXINIT[/green]",
        border_style="cyan"
    ))

    assets = []
    if demo:
        console.print("[bold yellow]ℹ️ Çevrimdışı SSH referans demo modu devrede.[/bold yellow]")
        assets = [
            {"name": f"{clean_host}-ssh-kex-ref", "algorithm": "diffie-hellman-group14-sha256", "type": "protocol", "key_size": 2048},
            {"name": f"{clean_host}-hostkey-ssh-rsa", "algorithm": "RSA-2048", "type": "key", "key_size": 2048},
        ]
    else:
        probe = NetworkProbe()
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task(f"[cyan]SSH_MSG_KEXINIT el sıkışması ({clean_host}:{port})...[/cyan]", total=None)
            res = probe.probe_ssh_endpoint(clean_host, port)
            progress.update(task, completed=True)

        if not res["connected"]:
            err_msg = res.get("error") or "SSH soket hatası"
            console.print(f"[bold red]❌ SSH sunucusuna bağlanılamadı ({err_msg}). Canlı hedef erişilebilir olmalı veya --demo kullanılmalıdır.[/bold red]")
            raise click.ClickException(f"SSH bağlantısı kurulamadı: {err_msg}")

        console.print(f"[dim]Sunucu Başlığı:[/dim] [bold]{res['server_banner']}[/bold]")
        pqc_kex = res.get("pqc_hybrid_kex", False)
        assets.append({
            "name": f"{clean_host}-ssh-kex",
            "algorithm": "mlkem768x25519-sha512@openssh.com" if pqc_kex else "diffie-hellman-group14-sha256",
            "type": "protocol",
            "key_size": 768 if pqc_kex else 2048,
        })
        for hk in res.get("host_key_algorithms", [])[:3]:
            assets.append({
                "name": f"{clean_host}-hostkey-{hk}",
                "algorithm": "RSA-2048" if "rsa" in hk else "ECDSA-P256",
                "type": "key",
                "key_size": 2048 if "rsa" in hk else 256,
            })

    engine = PQScanEngine()
    report = engine.assess_target(target=f"{clean_host}:{port}", detected_assets=assets)
    _render_report_table(report)

    if output_cbom:
        with open(output_cbom, "w", encoding="utf-8") as f:
            f.write(report.cbom.model_dump_json(by_alias=True, indent=2))
        console.print(f"[bold green]✅ CycloneDX 1.6 CBOM kaydedildi:[/bold green] {output_cbom}")

    if output_csv:
        _export_csv(report, output_csv)
        console.print(f"[bold green]📊 Envanter CSV kaydedildi:[/bold green] {output_csv}")

    if html:
        html_content = generate_cockpit_html(report)
        with open(html, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[bold green]✨ Executive Cockpit kaydedildi:[/bold green] {html}")


@main.command(name="scan-dir")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("--shelf-life", "-x", default=10.0, help="Data shelf-life in years")
@click.option("--output-cbom", "-o", type=click.Path(), help="Export CycloneDX 1.6 CBOM to JSON")
@click.option("--output-csv", type=click.Path(), help="Export assets to CSV")
@click.option("--html", type=click.Path(), help="Export Cockpit to HTML file")
def scan_dir(directory: str, shelf_life: float, output_cbom: str | None, output_csv: str | None, html: str | None):
    """Scan a local directory for certificates, keys, and cryptographic debt."""
    console.print(f"[bold cyan]📂 Yerel dizin taranıyor:[/bold cyan] {directory}")

    scanner = LocalScanner()
    assets = scanner.scan_directory(directory)
    console.print(f"[dim]Bulunan kriptografik varlık sayısı: {len(assets)}[/dim]")

    engine = PQScanEngine()
    report = engine.assess_target(
        target=str(Path(directory).resolve()),
        detected_assets=assets,
        shelf_life_years=shelf_life,
    )

    table = Table(title=f"Yerel Dizin CBOM Denetimi: {directory}")
    table.add_column("Varlık", style="bold white")
    table.add_column("Algoritma", style="cyan")
    table.add_column("Tip", style="yellow")
    table.add_column("Konum", style="dim")

    for a in assets[:15]:
        table.add_row(a.get("name", "n/a"), a.get("algorithm", "n/a"), a.get("type", "n/a"), a.get("location", "n/a"))
    if len(assets) > 15:
        table.add_row(f"... ve {len(assets)-15} varlık daha", "", "", "")

    console.print(table)
    console.print(f"Genel Derece: [bold]{report.overall_grade.value}[/bold] (PQRI: {report.pqri_score})")

    if output_cbom:
        with open(output_cbom, "w", encoding="utf-8") as f:
            f.write(report.cbom.model_dump_json(by_alias=True, indent=2))
        console.print(f"[green]✅ CBOM kaydedildi:[/green] {output_cbom}")

    if output_csv:
        _export_csv(report, output_csv)
        console.print(f"[green]📊 CSV kaydedildi:[/green] {output_csv}")

    if html:
        html_content = generate_cockpit_html(report)
        with open(html, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[green]✨ HTML Rapor kaydedildi:[/green] {html}")


@main.command(name="report")
@click.option("--cbom", "-c", required=True, type=click.Path(exists=True), help="Path to CycloneDX 1.6 CBOM JSON")
@click.option("--output-html", type=click.Path(), help="Export Executive Cockpit to HTML file")
@click.option("--html", type=click.Path(), help="Export Executive Cockpit to HTML file (alias)")
@click.option("--output-csv", type=click.Path(), help="Export cryptographic inventory to CSV")
@click.option("--output-json", type=click.Path(), help="Export Assessment Report to JSON")
def report(cbom: str, output_html: str | None, html: str | None, output_csv: str | None, output_json: str | None):
    """Generate executive cockpit and compliance reports from an existing CBOM."""
    with open(cbom, "r", encoding="utf-8") as f:
        cbom_data = json.load(f)

    assets = []
    for comp in cbom_data.get("components", []):
        crypto = comp.get("cryptoProperties", {})
        algo_name = crypto.get("algorithmProperties", {}).get("name") or crypto.get("algorithmName", "Unknown")
        assets.append({
            "name": comp.get("name", "unnamed"),
            "algorithm": algo_name,
            "type": crypto.get("assetType", "algorithm"),
            "key_size": crypto.get("keyLength") or crypto.get("keySize", 2048),
            "oid": crypto.get("oid"),
        })

    target_name = cbom_data.get("metadata", {}).get("component", {}).get("name", "CBOM-Report")
    engine = PQScanEngine()
    rep = engine.assess_target(target_name, assets)

    _render_report_table(rep)

    html_path = output_html or html
    if html_path:
        html_content = generate_cockpit_html(rep)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[bold green]✨ Executive Cockpit kaydedildi:[/bold green] {html_path}")

    if output_csv:
        _export_csv(rep, output_csv)
        console.print(f"[bold green]📊 Envanter CSV kaydedildi:[/bold green] {output_csv}")

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            f.write(rep.model_dump_json(indent=2))
        console.print(f"[bold green]📄 Rapor JSON kaydedildi:[/bold green] {output_json}")


@main.command(name="simulate")
@click.option("--iterations", "-n", default=10000, help="Number of Monte Carlo iterations")
@click.option("--seed", "-s", default=42, type=int, help="Random seed for deterministic replay")
@click.option("--shelf-life", "-x", default=10.0, help="Scale parameter for data shelf-life X (Weibull)")
@click.option("--migration-min", default=2.0, help="Minimum migration time in years")
@click.option("--migration-max", default=6.0, help="Maximum migration time in years")
@click.option("--crqc-mean", default=8.5, help="Mean years until CRQC (Q-Day)")
@click.option("--crqc-std", default=1.8, help="Standard deviation of CRQC arrival")
@click.option("--crqc-year", default=None, type=float, help="Estimated CRQC arrival calendar year (e.g. 2033.0)")
@click.option("--output-json", "-o", type=click.Path(), default=None, help="Export simulation results to JSON")
def simulate(
    iterations: int,
    seed: int,
    shelf_life: float,
    migration_min: float,
    migration_max: float,
    crqc_mean: float,
    crqc_std: float,
    crqc_year: float | None,
    output_json: str | None,
):
    """Run pure-Python deterministic Monte Carlo Q-Day stochastic stress simulation."""
    if crqc_year is not None:
        crqc_mean = max(1.0, crqc_year - 2026.0)

    console.print(Panel.fit(
        f"[bold magenta]🎲 Mosca Eşitsizliği Monte Carlo Q-Day Simülatörü[/bold magenta]\n"
        f"İterasyon: [bold white]{iterations:,}[/bold white] · Seed: [bold white]{seed}[/bold white] · Model: [cyan]Weibull(X) + Beta(Y) vs Normal(Z)[/cyan]",
        border_style="magenta"
    ))

    engine = PQScanEngine()
    result = engine.run_monte_carlo(
        iterations=iterations,
        seed=seed,
        shelf_life_scale=shelf_life,
        migration_min=migration_min,
        migration_max=migration_max,
        crqc_mean=crqc_mean,
        crqc_std=crqc_std,
    )

    tbl = Table(title="Monte Carlo Simülasyon Sonuçları")
    tbl.add_column("Parametre / İstatistik", style="bold yellow")
    tbl.add_column("Değer", style="white")

    tbl.add_row("HNDL Zafiyet Riski (P[X+Y > Z])", f"[bold red]%{result.vulnerability_probability * 100:.2f}[/bold red]")
    tbl.add_row("%95 Güven Aralığı (CI)", f"[%{result.confidence_interval_95[0]*100:.2f}, %{result.confidence_interval_95[1]*100:.2f}]")
    tbl.add_row("Ortalama Veri Raf Ömrü (E[X])", f"{result.mean_shelf_life_years:.2f} Yıl")
    tbl.add_row("Ortalama Göç Süresi (E[Y])", f"{result.mean_migration_time_years:.2f} Yıl")
    tbl.add_row("Ortalama CRQC Q-Day (E[Z])", f"{result.mean_crqc_arrival_years:.2f} Yıl")

    console.print(tbl)

    # ASCII Bar Distribution
    console.print("\n[bold cyan]📊 Stokastik Dağılım Histogramı ((X + Y) - Z farkı):[/bold cyan]")
    max_c = max(b["count"] for b in result.distribution_bins) if result.distribution_bins else 1
    for b in result.distribution_bins:
        r_str = f"[{b['range'][0]:5.1f} to {b['range'][1]:5.1f}]"
        bar_len = int((b["count"] / max_c) * 40)
        bar = "█" * bar_len
        color = "red" if b["range"][0] >= 0 else "green"
        console.print(f"  {r_str} | [{color}]{bar:<40}[/{color}] {b['count']:,}")

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            f.write(result.model_dump_json(indent=2))
        console.print(f"[bold green]✅ Simülasyon sonuçları JSON kaydedildi:[/bold green] {output_json}")


@main.command(name="attest")
@click.argument("target", required=False)
@click.option("--cbom", "-c", type=click.Path(exists=True), help="Path to existing CycloneDX 1.6 CBOM JSON")
@click.option("--port", "-p", default=443, help="Target network port (default: 443)")
@click.option("--issuer-did", default="did:pqh:auditor-node-01", help="Auditor decentralized identifier (DID)")
@click.option("--demo", is_flag=True, default=False, help="Run with offline reference attestation data")
@click.option("--output-vc", "-o", type=click.Path(), help="Export W3C Verifiable Credential to JSON")
@click.option("--contract-params", is_flag=True, default=False, help="Print EVM on-chain calldata parameters for PQHavenRegistry.sol")
def attest(
    target: str | None,
    cbom: str | None,
    port: int,
    issuer_did: str,
    demo: bool,
    output_vc: str | None,
    contract_params: bool,
):
    """Generate CBOM Merkle root and W3C Verifiable Credential for on-chain attestation."""
    if not target and not cbom:
        raise click.ClickException("Lütfen bir hedef belirtin veya '--cbom' dosyası sağlayın.")

    engine = PQScanEngine()
    assets = []
    report_target = target or "cbom-attestation"
    probe_health: Optional[Dict[str, int]] = None  # DALGA-D10: None = kanit local-CBOM'dan

    if cbom:
        with open(cbom, "r", encoding="utf-8") as f:
            cbom_data = json.load(f)
        for comp in cbom_data.get("components", []):
            crypto = comp.get("cryptoProperties", {})
            algo_name = crypto.get("algorithmProperties", {}).get("name") or crypto.get("algorithmName", "Unknown")
            assets.append({
                "name": comp.get("name", "unnamed"),
                "algorithm": algo_name,
                "type": crypto.get("assetType", "algorithm"),
                "key_size": crypto.get("keyLength") or crypto.get("keySize", 2048),
                "oid": crypto.get("oid"),
            })
        report_target = cbom_data.get("metadata", {}).get("component", {}).get("name", report_target)
        console.print(f"[bold cyan]🔏 CBOM dosyasından Kriptografik Tasdik üretiliyor:[/bold cyan] {cbom}")
        report = engine.assess_target(report_target, assets)
    else:
        target_raw = target.replace("https://", "").replace("http://", "").split("/")[0]
        if ":" in target_raw:
            clean_host, port_str = target_raw.split(":", 1)
            if port == 443 and port_str.isdigit():
                port = int(port_str)
        else:
            clean_host = target_raw

        console.print(f"[bold cyan]🔏 Kriptografik Tasdik (Attestation) üretiliyor:[/bold cyan] {clean_host}:{port}")

        if demo:
            console.print("[bold yellow]ℹ️ Çevrimdışı referans demo tasdik modu devrede.[/bold yellow]")
            assets = [
                {"name": f"{clean_host}-endpoint", "algorithm": "ECDH-X25519", "type": "protocol", "key_size": 256},
                {"name": f"{clean_host}-ref-rsa", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048}
            ]
        else:
            probe = NetworkProbe()
            probe_result = probe.probe_tls_endpoint(clean_host, port)

            if not probe_result["connected"]:
                err_msg = probe_result.get("error") or "Soket bağlantı hatası"
                console.print(f"[bold red]❌ Hedefe bağlanılamadı ({err_msg}). Canlı hedef erişilebilir olmalı veya --demo kullanılmalıdır.[/bold red]")
                raise click.ClickException(f"Tasdik için hedefe bağlanılamadı: {err_msg}")

            assets.append({
                "name": f"{clean_host}-endpoint",
                "algorithm": probe_result.get("kex_group", "ECDH-X25519"),
                "type": "protocol",
                "key_size": 768 if probe_result.get("pqc_hybrid_kex") else 256,
            })
            for cert in probe_result.get("certificates", []):
                assets.append({
                    "name": f"{clean_host}-cert",
                    "algorithm": cert["algorithm"],
                    "type": "certificate",
                    "key_size": cert["key_size"],
                })
            probe_health = {
                "total": 1,
                "connected": 1,
                "probe_errors": 1 if probe_result.get("probe_error") else 0,
            }
        report = engine.assess_target(
            clean_host,
            assets,
            probe_health=probe_health,
        )

    vc = engine.generate_verifiable_credential(report, issuer_did=issuer_did)

    console.print(Panel.fit(
        f"[bold green]✨ Kriptografik Tasdik Başarıyla Üretildi![/bold green]\n"
        f"Hedef: [bold white]{report.target}[/bold white]\n"
        # DALGA-D10 (PQH-NET-2): N/A icin "None / 100" basma
        f"PQRI Skoru: [bold yellow]{'N/A' if report.pqri_is_na else f'{report.pqri_score} / 100'}[/bold yellow] ({report.overall_grade.value})\n"
        f"CBOM Merkle Root: [bold cyan]0x{report.merkle_root}[/bold cyan]\n"
        f"W3C VC ID: [dim]{vc.id}[/dim]\n"
        f"On-Chain Kontrat: [dim]0x446B847e096B408B48B4bEeeFd0F4D3C23B99511 (PQHavenRegistry)[/dim]",
        border_style="green"
    ))

    if contract_params:
        grade_map = {
            "CRITICAL": 0,
            "HIGH": 1,
            "TRANSITIONAL": 2,
            "READY": 3,
            # DALGA-D10 (PQH-NET-2): N/A 0 (CRITICAL gibi) - hazir degil
            "UNKNOWN": 0,
        }
        entity_id = "0x" + hashlib.sha256(report.target.encode("utf-8")).hexdigest()
        cbom_merkle_root = f"0x{report.merkle_root}" if report.merkle_root else "0x" + "00" * 32
        pqri_basis = int(round(report.pqri_score * 100))
        status_grade = grade_map.get(report.overall_grade.value, 0)

        console.print(Panel.fit(
            f"[bold green]⛓️ EVM On-Chain Kontrat Parametreleri (PQHavenRegistry.registerAssessment):[/bold green]\n\n"
            f"• [bold cyan]entityId[/bold cyan] (bytes32): [white]{entity_id}[/white]\n"
            f"• [bold cyan]cbomMerkleRoot[/bold cyan] (bytes32): [white]{cbom_merkle_root}[/white]\n"
            f"• [bold cyan]pqriScore[/bold cyan] (uint16): [yellow]{pqri_basis}[/yellow] (%{report.pqri_score:.2f})\n"
            f"• [bold cyan]statusGrade[/bold cyan] (uint8): [magenta]{status_grade}[/magenta] ({report.overall_grade.value})\n"
            f"• [bold cyan]auditorDid[/bold cyan] (string): [white]\"{issuer_did}\"[/white]\n\n"
            f"[dim]Solidity Tuple:[/dim]\n"
            f"(\"{entity_id}\", \"{cbom_merkle_root}\", {pqri_basis}, {status_grade}, \"{issuer_did}\")",
            border_style="green"
        ))

    if output_vc:
        with open(output_vc, "w", encoding="utf-8") as f:
            f.write(vc.model_dump_json(by_alias=True, indent=2))
        console.print(f"[bold green]✅ W3C Verifiable Credential kaydedildi:[/bold green] {output_vc}")


@main.command(name="serve")
@click.option("--target", "-t", default="api.acme.internal", help="Target name for assessment")
@click.option("--cbom", "-c", type=click.Path(exists=True), help="Path to existing CycloneDX 1.6 CBOM JSON file")
@click.option("--port", "-p", default=8443, help="HTTP server port")
@click.option("--open-browser", is_flag=True, default=True, help="Auto-open browser")
def serve(target: str, cbom: str | None, port: int, open_browser: bool):
    """Launch interactive local Post-Quantum Telemetry Cockpit."""
    engine = PQScanEngine()

    if cbom:
        with open(cbom, "r", encoding="utf-8") as f:
            cbom_data = json.load(f)
        assets = []
        for comp in cbom_data.get("components", []):
            crypto = comp.get("cryptoProperties", {})
            algo_name = crypto.get("algorithmProperties", {}).get("name") or crypto.get("algorithmName", "Unknown")
            assets.append({
                "name": comp.get("name", "unnamed"),
                "algorithm": algo_name,
                "type": crypto.get("assetType", "algorithm"),
                "key_size": crypto.get("keyLength") or crypto.get("keySize", 2048),
            })
        target_name = cbom_data.get("metadata", {}).get("component", {}).get("name") or target
        report = engine.assess_target(target_name, assets)
    else:
        assets = [
            {"name": f"{target}-edge-tls", "algorithm": "RSA-2048", "type": "certificate", "key_size": 2048},
            {"name": f"{target}-mesh-kex", "algorithm": "ECDH-X25519", "type": "protocol", "key_size": 256},
            {"name": f"{target}-db-storage", "algorithm": "AES-128", "type": "algorithm", "key_size": 128},
            {"name": f"{target}-auth-signer", "algorithm": "ML-DSA-65", "type": "algorithm", "key_size": 192},
        ]
        report = engine.assess_target(target, assets)

    html_content = generate_cockpit_html(report)

    class CockpitHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html_content.encode("utf-8"))

        def log_message(self, format, *args):
            pass

    console.print(Panel.fit(
        f"[bold green]🚀 PQHaven Telemetry Cockpit Canlı![/bold green]\n"
        f"URL: [bold cyan]http://localhost:{port}[/bold cyan]\n"
        f"Kapatmak için: [dim]Ctrl + C[/dim]",
        border_style="green"
    ))

    if open_browser:
        webbrowser.open(f"http://localhost:{port}")

    with socketserver.TCPServer(("", port), CockpitHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[yellow]Kokpit sunucusu durduruldu.[/yellow]")


def _export_csv(report, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("Name,Type,Algorithm,KeySize,NistLevel,ShorVulnerable,RecommendedReplacement\n")
        for c in report.cbom.components:
            p = c.crypto_properties
            f.write(f'"{c.name}","{p.asset_type.value}","{p.algorithm_name}",{p.key_size},{p.nist_quantum_level},{p.shor_vulnerable},"{p.recommended_replacement}"\n')


def _render_report_table(report):
    table = Table(title=f"📊 Kriptografik Denetim Raporu: {report.target}")
    table.add_column("Metrik / Parametre", style="bold yellow")
    table.add_column("Değer", style="white")

    color_map = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange3",
        "TRANSITIONAL": "bold yellow",
        "READY": "bold green",
        # DALGA-D10 (PQH-NET-2): N/A kirmizi-beyaz - "hazir" rengi DEGIL
        "UNKNOWN": "bold white on red",
    }
    gcolor = color_map.get(report.overall_grade.value, "white")

    # DALGA-D10 (PQH-NET-2): N/A icin "None / 100" basmak TEHLIKELI
    # (None sayi degil; "0.0" gibi okunabilir). Skor yoksa N/A bas.
    # getattr: geri-uyumluluk (dummy report nesneleri yeni alani tasiyamayabilir).
    pqri_na = bool(getattr(report, "pqri_is_na", report.pqri_score is None))
    none_reason = getattr(report, "none_reason", None)
    pqri_cell = "N/A (olculemedi)" if pqri_na else f"{report.pqri_score} / 100"
    grade_cell = f"[{gcolor}]{report.overall_grade.value}[/{gcolor}]"
    if pqri_na and none_reason:
        grade_cell += f" [bright_red]({none_reason})[/bright_red]"
    table.add_row("PQRI Risk Skoru", pqri_cell)
    table.add_row("Kuantum Hazırlık Derecesi", grade_cell)
    table.add_row("HNDL Tehditli Varlık", str(report.hndl_vulnerability_count))
    table.add_row("Toplam CBOM Varlığı", str(len(report.cbom.components)))
    table.add_row("CBOM Merkle Root", f"[cyan]0x{report.merkle_root}[/cyan]" if report.merkle_root else "Yok")
    table.add_row(
        "Mevzuat Bayrakları",
        "\n".join(f"• {f}" for f in report.compliance_flags) if report.compliance_flags else "[green]Uyumsuzluk Yok[/green]"
    )
    console.print(table)


@main.command(name="export-issues")
@click.option("--cbom", "-c", required=True, type=click.Path(exists=True), help="Path to CycloneDX 1.6 CBOM JSON")
@click.option("--format", "-f", "target_format", type=click.Choice(["github", "jira"], case_sensitive=False), default="github", help="Ticket export format")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output path for exported tickets JSON")
def export_issues(cbom: str, target_format: str, output: str):
    """Export Min-Cut DAG migration roadmap as GitHub Issues or Jira tickets."""
    console.print(Panel.fit(
        f"[bold cyan]🎫 PQHaven Görev İhracı: {target_format.upper()}[/bold cyan]\n"
        f"Girdi: [dim]{cbom}[/dim] -> Çıktı: [bold green]{output}[/bold green]",
        border_style="cyan"
    ))

    with open(cbom, "r", encoding="utf-8") as f:
        cbom_data = json.load(f)

    engine = PQScanEngine()
    assets = []
    for comp in cbom_data.get("components", []):
        crypto = comp.get("cryptoProperties", {})
        algo_name = crypto.get("algorithmProperties", {}).get("name", "Unknown")
        assets.append({
            "name": comp.get("name", "unnamed"),
            "algorithm": algo_name,
            "type": crypto.get("assetType", "algorithm"),
            "key_size": crypto.get("keyLength", 2048),
        })

    target_name = cbom_data.get("metadata", {}).get("component", {}).get("name", "ExportTarget")
    report = engine.assess_target(target_name, assets)
    tickets = engine.export_migration_tickets(report, target_format=target_format.lower())

    with open(output, "w", encoding="utf-8") as f:
        json.dump(tickets, f, indent=2, ensure_ascii=False)

    console.print(f"[bold green]✅ {len(tickets)} adet {target_format.upper()} bileti başarıyla oluşturuldu:[/bold green] {output}")


@main.command(name="auto-discover")
@click.option("--output-cbom", "-c", default="auto_cbom.json", help="Path to output CBOM")
def auto_discover(output_cbom: str):
    """Autonomously discover local open listening ports and system cryptographic assets."""
    console.print(Panel.fit("[bold cyan]🔍 PQHaven Otonom Varlık ve Port Keşfi[/bold cyan]", border_style="cyan"))

    probe = NetworkProbe(timeout=0.5)
    test_ports = [443, 8443, 9443, 22, 8080]
    discovered_endpoints = []

    for p in test_ports:
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=0.2):
                discovered_endpoints.append(f"127.0.0.1:{p}")
        except Exception:
            pass

    scanner = LocalScanner()
    local_assets = scanner.scan_directory(Path("."))

    for ep in discovered_endpoints:
        host, port_str = ep.split(":")
        port = int(port_str)
        if port == 22:
            res = probe.probe_ssh_endpoint(host, port)
        else:
            res = probe.probe_tls_endpoint(host, port)
        if res.get("connected"):
            local_assets.append({
                "name": f"{ep}-protocol",
                "algorithm": res.get("kex_group", "ECDH-X25519"),
                "type": "protocol",
                "key_size": 256,
            })

    engine = PQScanEngine()
    report = engine.assess_target("auto-discovered-host", local_assets)
    cbom_json = report.cbom.model_dump_json(by_alias=True, indent=2)
    with open(output_cbom, "w", encoding="utf-8") as f:
        f.write(cbom_json)

    console.print(f"[bold green]✅ {len(report.cbom.components)} kriptografik varlık otonom keşfedildi:[/bold green] {output_cbom}")
    _render_report_table(report)


@main.command(name="gatekeep")
@click.option("--path", "-p", default=".", help="Repository path to audit")
@click.option("--max-pqri", default=40.0, help="Maximum allowed PQRI risk score")
@click.option("--fail-on-shor/--no-fail-on-shor", default=True, help="Block build if any Shor-vulnerable algorithm is found")
@click.option("--install-hook", is_flag=True, default=False, help="Install Git pre-commit hook in .git/hooks/pre-commit")
def gatekeep(path: str, max_pqri: float, fail_on_shor: bool, install_hook: bool):
    """Autonomous CI/CD and Git pre-commit policy gatekeeper."""
    if install_hook:
        git_dir = Path(path) / ".git"
        if not git_dir.is_dir():
            git_dir = Path(".git")
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_path = hooks_dir / "pre-commit"
        hook_content = (
            "#!/bin/sh\n"
            "# PQHaven Autonomous Pre-Commit Gatekeeper\n"
            "pqscan gatekeep --path . --max-pqri 40.0 --fail-on-shor\n"
        )
        hook_path.write_text(hook_content, encoding="utf-8")
        try:
            hook_path.chmod(0o755)
        except Exception as exc:
            # DALGA-C-2 (PQH-CLI-1) DUZELTILDI: chmod başarısız olursa "✅ kuruldu"
            # basılıyordu — güvenlik-kapısı fiilen-kapalıyken yeşil-ışık. Artık
            # fail-closed: kanca çalıştırılabilir değilse kurulum BAŞARISIZ sayılır.
            raise click.ClickException(
                f"Pre-commit kancası yazıldı ama çalıştırılabilir yapılamadı "
                f"(chmod hatası: {exc}). Elle düzelt: chmod +x {hook_path}"
            )
        # çalıştırılabilir-bit gerçekten-set-edildi-mi doğrula
        if not hook_path.stat().st_mode & 0o111:
            raise click.ClickException(
                f"Pre-commit kancası çalıştırılabilir değil: {hook_path} "
                f"( mode={oct(hook_path.stat().st_mode)})"
            )
        console.print(f"[bold green]✅ Git pre-commit kancası kuruldu:[/bold green] {hook_path}")
        return

    scanner = LocalScanner()
    assets = scanner.scan_directory(Path(path))
    engine = PQScanEngine()
    report = engine.assess_target("gatekeeper-audit", assets)

    has_shor = report.hndl_vulnerability_count > 0
    # DALGA-D10 (PQH-NET-2): N/A (None) > max_pqri kiyaslamasi TypeError -
    # kanit yetersizligi skipped (False) yerine tehlikeli kabul edilmeli.
    score_exceeded = (report.pqri_score is not None and report.pqri_score > max_pqri)
    score_na = report.pqri_score is None

    if (fail_on_shor and has_shor) or score_exceeded or score_na:
        pqri_txt = "N/A (ölçülemedi)" if score_na else f"{report.pqri_score} / 100"
        console.print(Panel.fit(
            f"[bold red]❌ GİT COMMIT / DERLEME REDDEDİLDİ (GATEKEEPER BLOCKED)![/bold red]\n\n"
            f"• PQRI Skoru: [bold yellow]{pqri_txt}[/bold yellow] (İzin verilen tavan: {max_pqri})\n"
            f"• Shor Zafiyetli Varlık Sayısı: [bold red]{report.hndl_vulnerability_count}[/bold red]\n\n"
            f"[dim]Kodu güvenli FIPS 203/204 algoritmalarıyla değiştirmek için:[/dim]\n"
            f"[bold cyan]pqscan fix --apply[/bold cyan]",
            border_style="red"
        ))
        raise SystemExit(1)

    console.print(f"[bold green]✅ Kapı Bekçisi Geçildi (PQRI: {report.pqri_score}, Shor Zafiyeti: 0)[/bold green]")


@main.command(name="daemon")
@click.option("--interval", "-i", default=3600, help="Scan interval in seconds")
@click.option("--targets", "-t", default="", help="Comma-separated network endpoints")
@click.option("--path", "-p", default=".", help="Local path to monitor")
@click.option("--webhook", "-w", default=None, help="SIEM / Slack alert webhook URL")
@click.option("--max-cycles", default=None, type=int, help="Exit after N cycles (for testing)")
def daemon(interval: int, targets: str, path: str, webhook: Optional[str], max_cycles: Optional[int]):
    """Launch autonomous 24/7 background sentinel watcher with webhook dispatch."""
    from pqhaven.daemon import SentinelDaemon

    console.print(Panel.fit(
        f"[bold green]👁️ PQHaven Sentinel Daemon Başlatıldı[/bold green]\n"
        f"Tarama Aralığı: [bold cyan]{interval}s[/bold cyan] | Webhook: [dim]{webhook or 'Yok'}[/dim]",
        border_style="green"
    ))

    t_list = [t.strip() for t in targets.split(",") if t.strip()]
    d = SentinelDaemon(interval_seconds=interval, webhook_url=webhook)
    d.run_loop(t_list, [path], max_cycles=max_cycles)


@main.command(name="fix")
@click.option("--path", "-p", default=".", help="Target directory to inspect and remediate")
@click.option("--apply", is_flag=True, default=False, help="Apply fixes directly in-place")
@click.option("--output-patch", "-o", default=None, help="Save unified diff patch to file")
def fix(path: str, apply: bool, output_patch: Optional[str]):
    """Autonomously refactor code and generate Post-Quantum remediation patches."""
    from pqhaven.remediator import CodeRemediator

    remediator = CodeRemediator()
    results = remediator.scan_and_remediate(Path(path), apply=apply)

    if not results:
        console.print("[bold green]✅ Düzeltilmesi gereken zafiyetli kod tespit edilmedi.[/bold green]")
        return

    console.print(f"[bold yellow]⚠️ {len(results)} dosyada kriptografik iyileştirme tespit edildi:[/bold yellow]")
    all_patches = []
    for r in results:
        status = "[bold green]UYGULANDI[/bold green]" if r["applied"] else "[bold cyan]YAMA HAZIR[/bold cyan]"
        console.print(f"  • {r['relative_path']} -> {status}")
        all_patches.append(r["patch"])

    if output_patch:
        with open(output_patch, "w", encoding="utf-8") as f:
            f.write("\n".join(all_patches))
        console.print(f"[bold green]✅ Birleşik yama dosyası kaydedildi:[/bold green] {output_patch}")


if __name__ == "__main__":
    main()



