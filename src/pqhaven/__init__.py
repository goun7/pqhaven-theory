"""PQHaven: Autonomous Cryptographic Bill of Materials (CBOM) Discovery & Post-Quantum Migration Decision Engine."""

# A1c-2026-10-22: surum-artik TEK-KAYNAKLI. Onceden pyproject.toml,
# __init__.py ve cli.py ayri ayri "2.0.0" tasiyordu ( 3-yazinim).
#
# Oncesi-tasarim ( importlib.metadata-only) BIR-GERCEK-KUSURU-ORTAYA-CIKARDI:
# kaynak-agacindan-kosarken importlib.metadata SITE-PACKAGES'taki-ESKI-kurulu
# pqhaven'i-buluyor ( 2.0.0), yeni-pyproject'i-degil - yani gelistirme-
# ortaminda __version__-yalan-soyluyordu. Olcum: metadata-path
# /home/gokun/.local/lib/python3.14/site-packages/pqhaven-2.0.0.dist-info.
#
# Duzeltme: ONCE-kaynak-agacindaki-pyproject.toml-okunur ( bu-deponun-tek-
# gercegi), YOKSA-importlib.metadata'ye-dusulur ( kurulu-paket-icin).
from pathlib import Path

_PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _kaynak_surumu():
    """Kaynak-agacindaki-pyproject.toml'den-version-okur ( yoksa-None)."""
    if not _PYPROJECT.exists():
        return None
    for ln in _PYPROJECT.read_text(encoding="utf-8").splitlines():
        if ln.startswith("version ="):
            return ln.split('"')[1]
    return None


_kaynak = _kaynak_surumu()
if _kaynak is not None:
    __version__ = _kaynak
else:  # kurulu-paket ( site-packages) - pyproject-agacta-yok
    from importlib.metadata import PackageNotFoundError, version as _dist_version

    try:
        __version__ = _dist_version("pqhaven")
    except PackageNotFoundError:
        __version__ = "0.0.0-dev"
