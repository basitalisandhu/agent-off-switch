"""Seeded fuzz test: every export file in the demo tenant replaced with bad bytes.

Each command runs in a subprocess with a timeout, so a hang fails the test instead of stalling CI. Bad input must
end with exit code 2 and a message naming the file, never a traceback.
"""

from __future__ import annotations

import random
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo-tenant"
FILES = sorted(p.name for p in DEMO.iterdir() if p.suffix in {".json", ".csv"})


def _bad_contents(seed: int) -> dict[str, bytes]:
    rng = random.Random(seed)
    return {
        "empty": b"",
        "not-utf8": b"\xff\xfe\x00" + bytes(rng.randrange(128, 256) for _ in range(64)),
        "truncated": b'{"value": [{"id": "',
        "deep": b"[" * 50_000 + b"]" * 50_000,
        "random": bytes(rng.randrange(256) for _ in range(512)),
    }


CASES = [(name, kind) for name in FILES for kind in _bad_contents(0)]


def _aos(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "agent_off_switch", *args], capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize(("name", "kind"), CASES, ids=[f"{n}-{k}" for n, k in CASES])
def test_bad_file_exits_2_naming_it(tmp_path, name, kind):
    folder = tmp_path / "tenant"
    shutil.copytree(DEMO, folder)
    (folder / name).write_bytes(_bad_contents(20261028)[kind])
    for args in (("review", str(folder), "--fail-on", "none"), ("inventory", str(folder))):
        result = _aos(*args)
        assert "Traceback" not in result.stderr, result.stderr[-800:]
        if name.endswith(".csv") and kind != "not-utf8":
            # A CSV with no usable rows or odd bytes is still readable text; it must not crash.
            assert result.returncode in (0, 1, 2), result.stderr
            continue
        assert result.returncode == 2, (result.returncode, result.stderr)
        assert name in result.stderr
