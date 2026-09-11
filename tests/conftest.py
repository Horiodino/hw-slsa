"""Parity mode: with HSLSA_BIN set, every verifier and chain producer the tamper
tests call runs through the Go binary instead of the Python module.

The fixtures still forge records with the Python signer, so each tamper case
checks that the Go verifier rejects a validly signed lie for the same reason,
with the same message, as the Python verifier did.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

BIN = os.environ.get("HSLSA_BIN")


def go(*args):
    proc = subprocess.run([BIN, *map(str, args)], capture_output=True, text=True)
    if proc.returncode == 0:
        return proc.stdout
    from hslsa.common import VerificationError

    err = proc.stderr.strip()
    if err.startswith("FAILED: "):
        raise VerificationError(err.removeprefix("FAILED: "))
    raise SystemExit(err)


def opt(flag, value):
    return [flag, value] if value else []


def lot_from(out, prefix):
    m = re.search(rf"{prefix}: PASSED for (\S+) sha256:(\w+)", out)
    return {"name": m.group(1), "digest": {"sha256": m.group(2)}} if m else None


def verify_run(bundle, trust, policy_path, units_path=None, vsa_key=None, vsa_dir=None):
    out = go("verify", "--bundle", bundle, "--trust-root", Path(bundle) / "trust-root.json", "--policy", policy_path,
             *opt("--units", units_path), *opt("--vsa-key", vsa_key), *opt("--vsa-out", vsa_dir))  # fmt: skip
    return {"final": lot_from(out, "tapeout check")}, {"lot": lot_from(out, "lot receipt check")}


def board_run(bundle, trust, policy_path, boards_path=None, vsa_key=None, vsa_dir=None):
    out = go("board", "verify", "--bundle", bundle, "--trust-root", Path(bundle) / "trust-root.json",
             "--policy", policy_path, *opt("--boards", boards_path), *opt("--vsa-key", vsa_key),
             *opt("--vsa-out", vsa_dir))  # fmt: skip
    return {"lot": lot_from(out, "board receipt check")}


def caliptra_verify(bundle, trust, policy_path, units_path, boots_dir, vsa_key=None, vsa_dir=None):
    go("caliptra", "verify", "--bundle", bundle, "--trust-root", Path(bundle) / "trust-root.json",
       "--policy", policy_path, "--units", units_path, "--boots", boots_dir,
       *opt("--vsa-key", vsa_key), *opt("--vsa-out", vsa_dir))  # fmt: skip


@pytest.fixture(autouse=True, scope="session")
def go_parity():
    if not BIN:
        yield
        return
    from hslsa import board, caliptra, design, hbom, mfg, verify

    mp = pytest.MonkeyPatch()
    mp.setattr(verify, "run", verify_run)
    mp.setattr(board, "run", board_run)
    mp.setattr(caliptra, "verify", caliptra_verify)
    mp.setattr(
        design,
        "release",
        lambda b, lock, key, tr, pol: go(
            "design", "release", "--bundle", b, "--lock", lock, "--key", key, "--trust-root", tr, "--policy", pol
        ),
    )
    mp.setattr(mfg, "run", lambda b, sc, keys: go("mfg", "--bundle", b, "--scenario", sc, "--keys", keys))
    mp.setattr(
        hbom,
        "build",
        lambda b, lock, sc, key: go("hbom", "--bundle", b, "--lock", lock, "--scenario", sc, "--key", key),
    )
    mp.setattr(
        caliptra,
        "release",
        lambda b, key, tr, pol: go(
            "caliptra", "design", "release", "--bundle", b, "--key", key, "--trust-root", tr, "--policy", pol
        ),
    )
    mp.setattr(
        caliptra,
        "hbom",
        lambda b, lock, sc, key: go("caliptra", "hbom", "--bundle", b, "--lock", lock, "--scenario", sc, "--key", key),
    )
    yield
    mp.undo()
