"""G42: README test-count pin - stale claims fail the build."""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def _collected_total(res_stdout: str) -> int:
    m = re.search(r"(\d+)\s+tests?\s+collected", res_stdout)
    if m:
        return int(m.group(1))
    total = 0
    for mm in re.finditer(r"^tests?/[\w./-]+\.py:\s*(\d+)\s*$", res_stdout, re.M):
        total += int(mm.group(1))
    return total


def test_readme_test_count_is_not_stale():
    assert README.exists(), "README.md yok"
    readme = README.read_text(encoding="utf-8").splitlines()
    claimed = None
    for ln in readme:
        m = re.search(r"\*\*(\d[\d.,]*)\s*test\s+passed", ln)
        if m:
            claimed = int(m.group(1).replace(".", "").replace(",", ""))
            break
    assert claimed is not None, "README test-sayisi-satiri-bulunamadi"

    res = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=900,
    )
    collected = _collected_total(res.stdout)
    assert collected > 0, f"collect-okunamadi: {res.stdout[-400:]}"
    assert collected == claimed, (
        "README-stale-test-sayisi: iddia=%d gercek=%d" % (claimed, collected)
    )
