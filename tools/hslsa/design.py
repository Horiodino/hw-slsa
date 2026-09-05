"""Design track: run a real RTL flow with open tools and attest every step.

Steps run here: 0 source freeze, 1 simulation (Icarus Verilog), 2 synthesis
(Yosys), and the tapeout release. Floorplan through GDS stream-out (steps 3
to 7) need OpenROAD and a PDK and are not run yet, so the release subject is
the gate-level netlist standing in for the final GDS.
"""

import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from .common import (
    DESIGN_FLOW,
    TrustRoot,
    VerificationError,
    builder,
    design_step_type,
    file_rd,
    load_signer,
    now,
    rd,
    read_json,
    sha256_file,
    sign,
    statement,
)

STEPS = ["source-freeze", "simulation", "synthesis"]


def att_name(step):
    index = {s: i for i, s in enumerate(STEPS)}
    return f"design-{index[step]}-{step}.intoto.json" if step in index else f"design-{step}.intoto.json"


def tool(name, version_args):
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"{name} is not installed")
    out = subprocess.run([name, *version_args], capture_output=True, text=True)
    version = (out.stdout or out.stderr).strip().splitlines()[0]
    return {"name": name, "version": version, "digest": {"sha256": sha256_file(os.path.realpath(path))}}


def predicate(step, external, deps, tools, checks, byproducts, started):
    run = builder()
    run["metadata"].update({"startedOn": started, "finishedOn": now()})
    run["byproducts"] = byproducts
    return {
        "buildDefinition": {
            "buildType": design_step_type(step),
            "externalParameters": external,
            "resolvedDependencies": deps,
        },
        "runDetails": run,
        "hwFlow": {"step": step, "tools": tools, "checks": checks},
    }


def check(name, ok, detail=""):
    return {"name": name, "result": "pass" if ok else "fail", "detail": detail}


def finish(bundle, step, subjects, pred, signer):
    sign(statement(subjects, DESIGN_FLOW, pred), signer, Path(bundle) / "att" / att_name(step))
    failed = [c["name"] for c in pred["hwFlow"]["checks"] if c["result"] != "pass"]
    if failed:
        raise SystemExit(f"{step}: gate failed: {', '.join(failed)} (failure recorded in the attestation)")
    print(f"{step}: ok, {len(subjects)} subject(s)")


def deterministic_tar(src_dir, files, out):
    """A tar that is byte-identical for identical inputs."""
    with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tar:
        for name in sorted(files):
            data = (Path(src_dir) / name).read_bytes()
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))


def unpack(archive, dest):
    with tarfile.open(archive) as tar:
        tar.extractall(dest, filter="data")


def source_freeze(bundle, lock_path, key, cache):
    """Step 0: fetch the pinned RTL, check every digest, and freeze it into one archive."""
    started = now()
    lock = read_json(lock_path)
    src = lock["source"]
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    deps, mismatched = [], []
    for name, want in sorted(src["files"].items()):
        path = cache / name
        if not path.exists():
            url = src["rawUrl"].format(commit=src["commit"], path=name)
            with urllib.request.urlopen(url, timeout=60) as resp:
                path.write_bytes(resp.read())
        got = sha256_file(path)
        if got != want:
            mismatched.append(f"{name} ({got})")
        deps.append(rd(name, got, uri=f"git+{src['repo']}@{src['commit']}#{name}"))
    if os.environ.get("GITHUB_SHA"):
        deps.append(
            {
                "name": "hw-slsa",
                "digest": {"gitCommit": os.environ["GITHUB_SHA"]},
                "uri": f"git+{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}",
            }
        )
    art = Path(bundle) / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    deterministic_tar(cache, src["files"], art / "source.tar")
    pred = predicate(
        "source-freeze",
        {"design": lock["design"], "repo": src["repo"], "commit": src["commit"]},
        deps,
        [],
        [check("inputs-pinned", not mismatched, "; ".join(mismatched) or "every file matches inputs.lock.json")],
        [],
        started,
    )
    finish(bundle, "source-freeze", [file_rd(art / "source.tar")], pred, load_signer(key))


def simulation(bundle, lock_path, key):
    """Step 1: run the testbench on the frozen source."""
    started = now()
    lock = read_json(lock_path)
    art = Path(bundle) / "artifacts"
    tools = [tool("iverilog", ["-V"]), tool("vvp", ["-V"])]
    with tempfile.TemporaryDirectory() as work:
        unpack(art / "source.tar", work)
        sim = lock["simulation"]
        build = subprocess.run(["iverilog", "-o", "tb", *sim["files"]], cwd=work, capture_output=True, text=True)
        run = (
            subprocess.run(["vvp", "-n", "tb"], cwd=work, capture_output=True, text=True)
            if build.returncode == 0
            else build
        )
    log = build.stdout + build.stderr + run.stdout + run.stderr
    (art / "simulation.log").write_text(log)
    ok_run = build.returncode == 0 and run.returncode == 0
    pred = predicate(
        "simulation",
        {"top": sim["top"], "files": sim["files"]},
        [file_rd(art / "source.tar")],
        tools,
        [
            check("testbench-ran", ok_run, f"exit {run.returncode}"),
            check("testbench-finished", "$finish called" in log, sim["passMarker"]),
            check(
                "activity",
                log.count(sim["activityMarker"]) >= sim["minActivity"],
                f"{log.count(sim['activityMarker'])} x '{sim['activityMarker']}'",
            ),
        ],
        [],
        started,
    )
    finish(bundle, "simulation", [file_rd(art / "simulation.log")], pred, load_signer(key))


def synthesis(bundle, lock_path, key):
    """Step 2: synthesize the frozen RTL to a gate-level netlist."""
    started = now()
    lock = read_json(lock_path)
    syn = lock["synthesis"]
    art = Path(bundle) / "artifacts"
    netlist = art / f"{syn['top']}.netlist.v"
    stat = art / "synthesis-stat.txt"
    script = (
        f"read_verilog {' '.join(syn['files'])}; synth -top {syn['top']} -flatten; "
        f"check -assert; tee -q -o {stat} stat; write_verilog -noattr {netlist}"
    )
    with tempfile.TemporaryDirectory() as work:
        unpack(art / "source.tar", work)
        proc = subprocess.run(["yosys", "-q", "-p", script], cwd=work, capture_output=True, text=True)
    (art / "synthesis.log").write_text(proc.stdout + proc.stderr)
    ok = proc.returncode == 0 and netlist.exists() and netlist.stat().st_size > 0
    pred = predicate(
        "synthesis",
        {"top": syn["top"], "script": script.replace(str(art) + "/", "")},
        [file_rd(art / "source.tar")],
        [tool("yosys", ["-V"])],
        [check("synthesis-and-check-assert", ok, f"exit {proc.returncode}")],
        [file_rd(art / "synthesis.log")],
        started,
    )
    subjects = [file_rd(netlist)] + ([file_rd(stat)] if stat.exists() else [])
    finish(bundle, "synthesis", subjects, pred, load_signer(key))


def release(bundle, lock_path, key, trust_root, policy):
    """Tapeout release: run the tapeout check, then sign the final design artifact."""
    from .verify import tapeout_check

    started = now()
    lock = read_json(lock_path)
    bundle = Path(bundle)
    final = bundle / "artifacts" / f"{lock['synthesis']['top']}.netlist.v"
    deps = [file_rd(bundle / "att" / att_name(s), f"att/{att_name(s)}") for s in STEPS]
    try:
        tapeout_check(bundle, TrustRoot.load(trust_root), read_json(policy), release=False)
        gate = check("tapeout-policy", True, "all design steps present, signed and linked")
    except VerificationError as e:
        gate = check("tapeout-policy", False, str(e))
    pred = predicate(
        "release",
        {
            "design": lock["design"],
            "finalArtifact": final.name,
            "finalArtifactKind": "gate-level netlist (stands in for GDS until steps 3 to 7 run)",
        },
        deps,
        [],
        [gate],
        [],
        started,
    )
    finish(bundle, "release", [file_rd(final)], pred, load_signer(key))
