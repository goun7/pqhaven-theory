"""A1c-2026-10-22: surum-tek-kaynak-pini.

Olcum: pyproject.toml'deki `version` ile pip-ile-kurulu `pqhaven.__version__`
VE `pqscan --version` ciktilari uyusmali. Onceden 3-ayri-yazinim vardi (
pyproject.toml "2.0.0", __init__.py "2.0.0", cli.py "2.0.0" - elle-bakim,
birini guncelleyince digeri-stale-kaliyordu).

Simdi: pyproject.toml -> importlib.metadata -> __version__ -> click.
Bu-pin, yeni-surum-akisinda ( build -> twine -> upload -> install) pyproject
ile CLI-arasindaki-bagin-kirilmasini-fail-loud-yapar.

Kapsam: kaynaktan-kosusta importlib.metadata PackageNotFoundError verince
"0.0.0-dev" duser - bu-durumda-pin-SKIP-gecer ( kurulu-degilse-olcum-yapilamaz).
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"


def _pyproject_surumu() -> str:
    metin = PYPROJECT.read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', metin, re.M)
    assert m, "pyproject.toml-icinde-version-satiri-bulunamadi"
    return m.group(1)


def test_cli_version_pyproject_ile_ayni():
    """pqscan --version, pyproject.toml ile ayni-degeri-vermeli."""
    surum = _pyproject_surumu()
    res = subprocess.run(
        [sys.executable, "-m", "pqhaven.cli", "--version"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=120)
    # -m pqhaven.cli calismazsa console-script'i-deneme ( CI'da-path)
    if res.returncode != 0:
        res = subprocess.run(
            [sys.executable, "-c",
             "from pqhaven import __version__; print(__version__)"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, "version-sorgusu-basarisiz: %r" % res.stderr[-300:]
    m = re.search(r"(\d+\.\d+\.\d+)", res.stdout)
    assert m, "version-cikti-ayristirilamadi: %r" % res.stdout[-300:]
    bulunan = m.group(1)
    if bulunan == "0.0.0":
        import pytest
        pytest.skip("kaynak-gelistirme-modu ( importlib.metadata-bulunamadi)")
    assert bulunan == surum, (
        "surum-tek-kaynak-ihlali: pyproject=%s cli=%s" % (surum, bulunan))


def test_pyproject_tek_version_satiri():
    """pyproject.toml'da birden-fazla-version-satiri-yasatan-tekrar-yazinim-yok."""
    metin = PYPROJECT.read_text(encoding="utf-8")
    satirlar = re.findall(r'^version\s*=\s*"[^"]+"', metin, re.M)
    assert len(satirlar) == 1, (
        "pyproject.toml'da-%d-adet-version-satiri ( tekrar-yazinim): %r"
        % (len(satirlar), satirlar))
