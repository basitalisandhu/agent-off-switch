import re
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import AS_OF, ROOT

from agent_off_switch import __version__, cli

PACKAGE = ROOT / "src" / "agent_off_switch"


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_bad_as_of_is_exit_2(demo, capsys):
    assert cli.main(["review", str(demo), "--as-of", "2026-13-45"]) == 2
    assert "YYYY-MM-DD" in capsys.readouterr().err


def test_bad_thresholds_are_exit_2(demo):
    assert cli.main(["inventory", str(demo), "--unused-days", "0"]) == 2


def test_python_dash_m_runs():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_off_switch",
            "review",
            str(ROOT / "examples" / "demo-tenant"),
            "--as-of",
            AS_OF,
            "--fail-on",
            "none",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "nobody owns" in result.stdout


def test_windows_style_relative_folder_argument(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    folder = "examples\\demo-tenant" if sys.platform == "win32" else "examples/demo-tenant"
    assert cli.main(["inventory", folder, "--as-of", AS_OF]) == 0
    assert "13 non-human identities" in capsys.readouterr().out


def test_package_has_no_network_or_subprocess_imports():
    banned = re.compile(r"^\s*(import|from)\s+(socket|subprocess|urllib|http|requests|ssl|ftplib|smtplib)\b", re.M)
    for path in PACKAGE.glob("*.py"):
        assert not banned.search(path.read_text(encoding="utf-8")), path.name


def repo_text_files():
    skip = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
    for path in ROOT.rglob("*"):
        if (
            path.is_file()
            and not skip & set(path.parts)
            and path.suffix in {".py", ".md", ".json", ".csv", ".yml", ".toml", ".txt", ""}
        ):
            yield path


def test_repository_has_no_em_dashes_or_other_key_literals():
    key = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
    em_dash = chr(0x2014)
    for path in repo_text_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert em_dash not in text, path
        assert set(key.findall(text)) <= {"AKIAIOSFODNN7EXAMPLE"}, path


def test_demo_tenant_uses_only_the_documentation_account():
    for path in (ROOT / "examples").rglob("*.json"):
        for account in re.findall(r"arn:aws:iam::(\d{12})", path.read_text(encoding="utf-8")):
            assert account == "111122223333", path


def test_written_files_use_unix_newlines(demo, tmp_path):
    out = tmp_path / "inv.csv"
    assert cli.main(["inventory", str(demo), "--as-of", AS_OF, "--format", "csv", "--out", str(out)]) == 0
    assert b"\r\n" not in Path(out).read_bytes()
