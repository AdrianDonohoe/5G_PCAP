"""The Golden baseline is byte-stable: regeneration reproduces it exactly."""

import subprocess
from pathlib import Path

BASELINE = Path(__file__).parent.parent / "baseline"


def test_regeneration_is_byte_stable(tmp_path):
    out = tmp_path / "golden_kpis.json"
    subprocess.run(
        [str(BASELINE / "regenerate.sh"), str(out)],
        check=True,
        capture_output=True,
    )
    assert out.read_bytes() == (BASELINE / "golden_kpis.json").read_bytes()
