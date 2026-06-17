"""Test harness for sourcing and exercising sh-keyring.shlib from pytest.

The library is a set of bash functions that shell out to external CLIs
(``security``, ``op``, ``aws``) and to ``date``/``sed``. To make every
scenario deterministic -- including "this CLI is not installed" -- each test
runs under a PATH that contains *only* a per-test stub directory. Real
baseline utilities (``bash``/``env``/``date``/``sed``/``cat``) are symlinked
into that directory so the library works; ``security``/``op``/``aws`` exist
only when a test stubs them, so their absence is controllable rather than
inherited from the host.
"""

import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REAL_PATH = os.environ.get("PATH", "")
SHLIB = str(Path(__file__).resolve().parent.parent / "sh-keyring.shlib")
BASH = shutil.which("bash") or "/bin/bash"
# Real utilities the library invokes; symlinked so PATH can be stub-only.
_BASELINE = ["bash", "env", "date", "sed", "cat"]


def _which(name):
    for directory in REAL_PATH.split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


class ShlibRunner:
    """Sources the library inside a stub-only PATH and runs a snippet."""

    def __init__(self, bindir):
        self.bindir = bindir
        for name in _BASELINE:
            real = _which(name)
            if real:
                (bindir / name).symlink_to(real)

    def stub(self, name, body):
        """Install an executable stub command named ``name``."""
        path = self.bindir / name
        if path.exists() or path.is_symlink():
            path.unlink()
        path.write_text("#!/usr/bin/env bash\n" + textwrap.dedent(body))
        path.chmod(0o755)

    def run(self, snippet, env=None):
        """Source the library, run ``snippet``, return the CompletedProcess."""
        full_env = {"PATH": str(self.bindir), "SHLIB": SHLIB}
        if env:
            full_env.update({k: str(v) for k, v in env.items()})
        script = 'source "${SHLIB}"\n' + textwrap.dedent(snippet)
        return subprocess.run(
            [BASH, "-c", script],
            capture_output=True,
            text=True,
            env=full_env,
        )


@pytest.fixture
def runner(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    return ShlibRunner(bindir)