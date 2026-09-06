"""Design track on a real RTL-to-GDS flow: OpenLane 2 with one signed attestation per step.

OpenLane runs in its pinned container. This process stays outside it, holds
the signing key, and watches the run directory: each time a step finishes
(OpenLane writes runtime.txt after state_out.json), the step's outputs are
hashed and a design-flow statement is signed before the next step's record.
The key never enters the container.

Each step record lists as resolvedDependencies the frozen source, the image,
the PDK tree, the step's own resolved config, every design view it received
(by digest, so they link to earlier subjects) and the previous record. Its
subjects are the views it produced plus its state_out.json, which carries
the metrics.

`compare` measures reproducibility between two runs of the same flow on
different builders: which step outputs are bit-exact, which differ only in
timestamps or line order, and which differ in content.
"""

import json
import math
import os
import re
import subprocess
import tempfile
import time
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
    sha256_bytes,
    sha256_file,
    sign,
    statement,
    write_json,
)
from .design import att_name, unpack
from .verify import as_slsa_provenance, decode

STEP_TYPE = design_step_type("openlane2")
RELEASE_ATT = "openlane-release.intoto.json"
STEP_DIR = re.compile(r"^(\d+)-(.+)$")

# Which binary in the image does the work, by OpenLane step id prefix.
TOOL_FOR_PREFIX = {
    "yosys": "yosys",
    "openroad": "openroad",
    "odb": "openroad",
    "magic": "magic",
    "klayout": "klayout",
    "netgen": "netgen",
    "verilator": "verilator",
}

# OpenLane step slugs mapped onto the spec's design steps 1 to 7 (first match wins).
SPEC_STEPS = [
    ("simulation", r"^(verilator-lint|checker-lint)"),
    ("synthesis", r"^(yosys-(jsonheader|synthesis)|checker-(yosys|netlistassign)|openroad-stapre)"),
    (
        "floorplan",
        r"^(openroad-(checksdcfiles|checkmacroinstances|floorplan|cutrows|tapendcapinsertion|generatepdn)"
        r"|odb-(checkmacroantenna|setpower|manualmacro|addpdn|removepdn|addrouting)|checker-powergrid)",
    ),
    (
        "place-cts",
        r"^(openroad-(globalplacement|ioplacement|repairdesignpostgpl|detailedplacement|cts|resizertimingpostcts)"
        r"|odb-(customio|applydef|writeverilog|manualglobal))",
    ),
    (
        "routing",
        r"^(openroad-(globalrouting|checkantennas|repairdesignpostgrt|repairantennas|resizertimingpostgrt"
        r"|detailedrouting|fillinsertion)|odb-(diodes|heuristicdiode|removerouting|reportdisconnected"
        r"|reportwire|cellfrequency)|checker-(trdrc|disconnected|wirelength))",
    ),
    ("gds-stream-out", r"^(magic-(streamout|writelef)|klayout-streamout)"),
    ("signoff", r"^(openroad-(rcx|sta|irdrop)|magic-|klayout-|netgen-|yosys-eqy|checker-|odb-check|misc-)"),
]

# Signoff gates on the final metrics. Required ones must be present and zero;
# optional ones must be zero when the flow reported them.
SIGNOFF_REQUIRED = ["route__drc_errors", "magic__drc_error__count", "design__lvs_error__count"]
SIGNOFF_OPTIONAL = [
    "klayout__drc_error__count",
    "design__xor_difference__count",
    "magic__illegal_overlap__count",
    "design__critical_disconnected_pin__count",
]

PROBE = r"""
import hashlib, json, os, shutil, subprocess
out = {}
for name, args in [("openlane", ["--version"]), ("yosys", ["-V"]), ("openroad", ["-version"]),
                   ("magic", ["--version"]), ("klayout", ["-v"]), ("netgen", None), ("verilator", ["--version"])]:
    p = shutil.which(name)
    if not p:
        continue
    real = os.path.realpath(p)
    with open(real, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    version = ""
    if args:
        try:
            r = subprocess.run([name, *args], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            lines = (r.stdout + r.stderr).strip().splitlines()
            version = lines[0].strip() if lines else ""
        except Exception as e:
            version = "unknown (%s)" % e
    out[name] = {"version": version, "digest": digest, "path": real}
print(json.dumps(out))
"""


def step_dirs(run_dir):
    """The flow's top-level step directories in execution order."""
    found = []
    for d in Path(run_dir).iterdir() if Path(run_dir).is_dir() else []:
        m = STEP_DIR.match(d.name)
        if d.is_dir() and m:
            found.append((int(m.group(1)), m.group(2), d))
    return sorted(found)


def spec_step(slug):
    for name, pattern in SPEC_STEPS:
        if re.match(pattern, slug):
            return name
    return "other"


def views(state, prefix=""):
    """(view key, path) for every file-valued design view in an OpenLane state."""
    for key, value in state.items():
        if not prefix and key == "metrics":
            continue
        k = f"{prefix}.{key}" if prefix else key
        if isinstance(value, str):
            yield k, value
        elif isinstance(value, dict):
            yield from views(value, k)
        elif isinstance(value, list):
            yield from views({str(i): v for i, v in enumerate(value)}, k)


def finite(value):
    """Metrics may hold inf or nan, which JSON and protobuf Struct cannot carry."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {k: finite(v) for k, v in value.items()}
    if isinstance(value, list):
        return [finite(v) for v in value]
    return value


def tree_digest(root):
    """One digest over a directory tree: sorted relative paths, file digests and symlink targets."""
    root = Path(root).resolve()
    lines = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                lines.append(f"L {rel} {os.readlink(path)}")
            else:
                lines.append(f"F {rel} {sha256_file(path)}")
    return sha256_bytes("\n".join(lines).encode())


class Flow:
    """Everything one attested OpenLane run needs, and the per-step signer."""

    def __init__(self, bundle, lock_path, key, work, pdk_root):
        self.bundle = Path(bundle)
        self.lock = read_json(lock_path)
        self.signer = load_signer(key)
        self.work = Path(work).resolve()
        self.pdk_root = Path(pdk_root).resolve()
        ol = self.lock["openlane"]
        self.design_dir = self.work / "design" / Path(ol["config"]).parent
        self.run_dir = self.design_dir / "runs" / ol["runTag"]
        self.meta = self.bundle / "openlane"
        self.attested = []  # [(ordinal, slug, att name)]

    # Setup

    def image(self):
        return self.lock["openlane"]["image"]

    def image_rd(self):
        ref, digest = self.image().split("@sha256:")
        return {"name": "openlane2-image", "uri": f"docker://{ref}", "digest": {"sha256": digest}}

    def probe_tools(self):
        out = subprocess.run(
            ["docker", "run", "--rm", self.image(), "python3", "-c", PROBE],
            capture_output=True,
            text=True,
            check=True,
        )
        tools = json.loads(out.stdout.strip().splitlines()[-1])
        write_json(self.meta / "tools.json", tools)
        return tools

    def pdk_rd(self):
        pdk = self.lock["pdk"]
        variant = self.pdk_root / pdk["variant"]
        if not variant.exists():
            raise SystemExit(f"PDK {variant} is missing; enable it with ciel first")
        info = {
            "name": pdk["variant"],
            "uri": f"{pdk['source']}#{pdk['family']}-{pdk['openPdksCommit']}",
            "digest": {"sha256": tree_digest(variant)},
            "annotations": {"kind": "pdk", "resolvedPath": str(variant.resolve().relative_to(self.pdk_root))},
        }
        write_json(self.meta / "pdk.json", info)
        return info

    def prepare(self):
        """Unpack the frozen source, record the image's tools and the PDK digest."""
        self.meta.mkdir(parents=True, exist_ok=True)
        src = self.bundle / "artifacts" / "source.tar"
        if (self.work / "design").exists():
            raise SystemExit(f"{self.work / 'design'} already exists; use a fresh work directory")
        unpack(src, self.work / "design")
        self.source = file_rd(src)
        self.source["annotations"] = {"kind": "source"}
        self.tools = self.probe_tools()
        self.pdk = self.pdk_rd()
        img = self.image_rd()
        img["annotations"] = {"kind": "toolchain"}
        self.common_deps = [self.source, img, self.pdk]

    def command(self):
        ol, pdk = self.lock["openlane"], self.lock["pdk"]
        tmp = tempfile.mkdtemp(prefix="hslsa-ol-")
        mounts = [f"{self.work}:{self.work}", f"{self.pdk_root}:{self.pdk_root}", f"{tmp}:/tmp"]
        env = ["TMPDIR=/tmp", "HOME=/tmp", f"PDK_ROOT={self.pdk_root}"]
        docker = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}", "-w", str(self.design_dir)]
        docker += [a for m in mounts for a in ("-v", m)] + [a for e in env for a in ("-e", e)]
        openlane = ["openlane", "--manual-pdk", "--pdk-root", str(self.pdk_root), "--pdk", pdk["variant"]]
        openlane += ["--scl", pdk["scl"], "--flow", ol["flow"], "--run-tag", ol["runTag"], Path(ol["config"]).name]
        return docker + [self.image()] + openlane

    # Per-step records

    def rel(self, path):
        rel = os.path.relpath(path, self.run_dir)
        return path if rel.startswith("..") else rel

    def attest(self, ordinal, slug, step_dir):
        step_dir = Path(step_dir)
        state_in = read_json(step_dir / "state_in.json")
        state_out = read_json(step_dir / "state_out.json")
        before = dict(views(state_in))

        subjects, produced = [], set()
        for key, path in views(state_out):
            p = Path(path)
            if before.get(key) == path or not p.is_file() or step_dir not in p.parents:
                continue
            subjects.append(rd(self.rel(path), sha256_file(p), annotations={"view": key}))
            produced.add(p.resolve())
        subjects.append(rd(self.rel(step_dir / "state_out.json"), sha256_file(step_dir / "state_out.json")))
        subjects[-1]["annotations"] = {"view": "state"}
        produced.add((step_dir / "state_out.json").resolve())

        deps = list(self.common_deps)
        deps.append(rd(self.rel(step_dir / "config.json"), sha256_file(step_dir / "config.json")))
        deps[-1]["annotations"] = {"kind": "step-config"}
        for key, path in sorted(before.items()):
            if Path(path).is_file():
                deps.append(rd(self.rel(path), sha256_file(path), annotations={"kind": "view", "view": key}))
        if self.attested:
            prev = self.attested[-1][2]
            deps.append(file_rd(self.bundle / "att" / prev, f"att/{prev}"))
            deps[-1]["annotations"] = {"kind": "previous-step"}

        skip = produced | {(step_dir / "config.json").resolve()}
        byproducts = [
            file_rd(p, self.rel(p))
            for p in sorted(step_dir.rglob("*"))
            if p.is_file() and not p.is_symlink() and p.resolve() not in skip
        ]

        m_in, m_out = state_in.get("metrics", {}), state_out.get("metrics", {})
        metrics = {k: v for k, v in m_out.items() if m_in.get(k) != v}
        tools = [self._tool("openlane")]
        if slug.split("-")[0] in TOOL_FOR_PREFIX:
            tools.append(self._tool(TOOL_FOR_PREFIX[slug.split("-")[0]]))

        run = builder()
        started = time.gmtime((step_dir / "state_in.json").stat().st_mtime)
        run["metadata"].update({"startedOn": time.strftime("%Y-%m-%dT%H:%M:%SZ", started), "finishedOn": now()})
        run["byproducts"] = byproducts
        pred = {
            "buildDefinition": {
                "buildType": STEP_TYPE,
                "externalParameters": {
                    "design": self.lock["design"],
                    "flow": self.lock["openlane"]["flow"],
                    "config": self.lock["openlane"]["config"],
                    "runTag": self.lock["openlane"]["runTag"],
                    "step": step_dir.name,
                },
                "resolvedDependencies": deps,
            },
            "runDetails": run,
            "hwFlow": {
                "step": spec_step(slug),
                "openlaneStep": slug,
                "ordinal": ordinal,
                "tools": tools,
                "checks": [{"name": "step-completed", "result": "pass", "detail": "state_out.json and runtime.txt"}],
                "metrics": finite(metrics),
            },
        }
        name = f"openlane-{ordinal:02d}-{slug}.intoto.json"
        sign(statement(subjects, DESIGN_FLOW, pred), self.signer, self.bundle / "att" / name)
        self.attested.append((ordinal, slug, name))
        print(f"  signed {name}: {len(subjects)} subject(s), {len(deps)} dependencies")

    def _tool(self, name):
        t = self.tools.get(name) or {}
        return {
            "name": name,
            "version": t.get("version", "not found in image"),
            "digest": {"sha256": t.get("digest", "")},
            "uri": self.image(),
        }

    def attest_ready(self):
        """Sign every finished step not yet signed, in order; stop at the first unfinished one."""
        done = {o for o, _, _ in self.attested}
        for ordinal, slug, d in step_dirs(self.run_dir):
            if ordinal in done:
                continue
            if not (d / "runtime.txt").exists():
                break
            self.attest(ordinal, slug, d)

    def run(self, poll=2.0):
        self.prepare()
        (self.bundle / "att").mkdir(parents=True, exist_ok=True)
        log = self.meta / "openlane.log"
        print(f"running OpenLane {self.lock['openlane']['version']} ({self.lock['openlane']['flow']} flow)")
        with open(log, "w") as out:
            proc = subprocess.Popen(self.command(), stdout=out, stderr=subprocess.STDOUT)
            while True:
                exited = proc.poll() is not None
                self.attest_ready()
                if exited:
                    break
                time.sleep(poll)
        unfinished = self.write_summary(proc.returncode)
        print(f"OpenLane exited {proc.returncode}; {len(self.attested)} steps signed")
        if proc.returncode != 0 or unfinished:
            raise SystemExit(f"OpenLane failed (exit {proc.returncode}, unfinished {unfinished}); see {log}")

    def write_summary(self, returncode):
        """run.json: the record list in order, the pinned inputs, and any step that never finished."""
        signed = {o for o, _, _ in self.attested}
        unfinished = [d.name for o, _, d in step_dirs(self.run_dir) if o not in signed]
        summary = {
            "exitCode": returncode,
            "steps": [{"ordinal": o, "step": s, "attestation": n} for o, s, n in self.attested],
            "unfinished": unfinished,
            "source": self.source,
            "image": self.image_rd(),
            "pdk": self.pdk,
            "runDir": str(self.run_dir),
            "workDir": str(self.work),
            "host": os.uname().nodename,
        }
        write_json(self.meta / "run.json", summary)
        return unfinished


def run(bundle, lock, key, work, pdk_root):
    Flow(bundle, lock, key, work, pdk_root).run()


# Verification


def fail(msg):
    raise VerificationError(msg)


def check_chain(bundle, run_dir, trust):
    """Verify every step record in order and return (records, subjects by digest)."""
    bundle, run_dir = Path(bundle), Path(run_dir)
    meta = read_json(bundle / "openlane" / "run.json")
    src = trust.open(bundle / "att" / att_name("source-freeze"), "flow-platform", DESIGN_FLOW)
    source_digest = file_rd(bundle / "artifacts" / "source.tar")["digest"]
    if src["subject"][0]["digest"] != source_digest:
        fail("source-freeze: source.tar does not match its attested digest")
    known = {source_digest["sha256"]: "source.tar"}
    records, prev = [], None
    if not meta["steps"]:
        fail("no OpenLane step records")
    for entry in meta["steps"]:
        label = f"openlane {entry['step']}"
        stmt = trust.open(bundle / "att" / entry["attestation"], "flow-platform", DESIGN_FLOW)
        as_slsa_provenance(stmt, label)
        pred = stmt["predicate"]
        if pred["buildDefinition"]["buildType"] != STEP_TYPE:
            fail(f"{label}: wrong buildType")
        if [c for c in pred["hwFlow"]["checks"] if c["result"] != "pass"]:
            fail(f"{label}: a gate failed")
        deps = pred["buildDefinition"]["resolvedDependencies"]
        kinds = {}
        for d in deps:
            kinds.setdefault(d.get("annotations", {}).get("kind"), []).append(d)
        if [d["digest"] for d in kinds.get("source", [])] != [source_digest]:
            fail(f"{label}: does not consume the frozen source")
        if [d["digest"] for d in kinds.get("toolchain", [])] != [meta["image"]["digest"]]:
            fail(f"{label}: does not name the pinned OpenLane image")
        if [d["digest"] for d in kinds.get("pdk", [])] != [meta["pdk"]["digest"]]:
            fail(f"{label}: does not name the PDK tree")
        for d in kinds.get("view", []):
            if d["digest"]["sha256"] not in known:
                fail(f"{label}: input view {d['name']} is not an output of any earlier step")
        want_prev = [] if prev is None else [file_rd(bundle / "att" / prev)["digest"]]
        if [d["digest"] for d in kinds.get("previous-step", [])] != want_prev:
            fail(f"{label}: not linked to the previous step record")
        for s in stmt["subject"]:
            path = run_dir / s["name"]
            if not path.is_file() or sha256_file(path) != s["digest"]["sha256"]:
                fail(f"{label}: subject {s['name']} is missing or does not match its digest")
            known[s["digest"]["sha256"]] = s["name"]
        records.append((entry, stmt))
        prev = entry["attestation"]
    missing = {"synthesis", "floorplan", "place-cts", "routing", "signoff", "gds-stream-out"} - {
        s["predicate"]["hwFlow"]["step"] for _, s in records
    }
    if missing:
        fail(f"spec steps with no OpenLane record: {', '.join(sorted(missing))}")
    return records, known


def final_gds(records):
    """The last GDS view produced, as (subject, record entry)."""
    found = None
    for entry, stmt in records:
        for s in stmt["subject"]:
            if s.get("annotations", {}).get("view") == "gds":
                found = (s, entry)
    if not found:
        fail("no step produced a GDS view")
    return found


def signoff(records):
    metrics = {}
    for _, stmt in records:
        metrics.update(stmt["predicate"]["hwFlow"]["metrics"])
    checks = []
    for name in SIGNOFF_REQUIRED + SIGNOFF_OPTIONAL:
        if name not in metrics:
            if name in SIGNOFF_REQUIRED:
                checks.append({"name": name, "result": "fail", "detail": "not reported"})
            continue
        ok = metrics[name] in (0, 0.0, "0")
        checks.append({"name": name, "result": "pass" if ok else "fail", "detail": f"{metrics[name]}"})
    return checks


def release(bundle, run_dir, key, trust_root, lock_path):
    """Tapeout release over the OpenLane run: check the chain and signoff, then sign the final GDS."""
    started = now()
    bundle = Path(bundle)
    lock = read_json(lock_path)
    try:
        records, _ = check_chain(bundle, run_dir, TrustRoot.load(trust_root))
        gds, producer = final_gds(records)
        checks = [{"name": "chain", "result": "pass", "detail": f"{len(records)} OpenLane step records linked"}]
        checks += signoff(records)
    except VerificationError as e:
        raise SystemExit(f"release refused: {e}") from e
    art = bundle / "artifacts"
    final = art / f"{lock['design']}.gds"
    final.write_bytes((Path(run_dir) / gds["name"]).read_bytes())
    deps = [file_rd(bundle / "att" / att_name("source-freeze"), f"att/{att_name('source-freeze')}")]
    deps += [file_rd(bundle / "att" / e["attestation"], f"att/{e['attestation']}") for e, _ in records]
    run = builder()
    run["metadata"].update({"startedOn": started, "finishedOn": now()})
    run["byproducts"] = []
    pred = {
        "buildDefinition": {
            "buildType": design_step_type("release"),
            "externalParameters": {
                "design": lock["design"],
                "finalArtifact": final.name,
                "finalArtifactKind": "GDSII",
                "producedBy": producer["attestation"],
                "producedAs": gds["name"],
            },
            "resolvedDependencies": deps,
        },
        "runDetails": run,
        "hwFlow": {"step": "release", "tools": [], "checks": checks},
    }
    sign(statement([file_rd(final)], DESIGN_FLOW, pred), load_signer(key), bundle / "att" / RELEASE_ATT)
    failed = [c["name"] for c in checks if c["result"] != "pass"]
    if failed:
        raise SystemExit(f"release: signoff gate failed: {', '.join(failed)} (recorded in the attestation)")
    print(f"release: {final.name} sha256:{sha256_file(final)} ({len(checks)} gates passed)")


def verify(bundle, run_dir, trust):
    """Buyer-side tapeout check for an OpenLane bundle."""
    bundle = Path(bundle)
    records, _ = check_chain(bundle, run_dir, trust)
    rel = trust.open(bundle / "att" / RELEASE_ATT, "tapeout-authority", DESIGN_FLOW)
    if rel["predicate"]["buildDefinition"]["buildType"] != design_step_type("release"):
        fail("release: wrong buildType")
    if [c for c in rel["predicate"]["hwFlow"]["checks"] if c["result"] != "pass"]:
        fail("release: a gate failed")
    want = {file_rd(bundle / "att" / e["attestation"])["digest"]["sha256"] for e, _ in records}
    got = {d["digest"]["sha256"] for d in rel["predicate"]["buildDefinition"]["resolvedDependencies"]}
    if not want <= got:
        fail("release: does not cover every OpenLane step record")
    gds, _ = final_gds(records)
    final = rel["subject"][0]
    if final["digest"] != gds["digest"]:
        fail("release: released GDS is not the flow's final GDS")
    path = bundle / "artifacts" / final["name"]
    if not path.is_file() or sha256_file(path) != final["digest"]["sha256"]:
        fail("release: GDS in the bundle does not match the release")
    return records, final


# Reproducibility


TS_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}[T _]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\w* +(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w* +\d+"
    r" +\d{1,2}:\d{2}:\d{2}(?: +[A-Z]{3,4})? +\d{4}",
    r"\d{1,2}/\d{1,2}/\d{2,4}(?: +\d{1,2}:\d{2}(?::\d{2})?)?",
    r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b",
    r"\b\d+(?:\.\d+)? ?(?:s|sec|secs|seconds|ms|MB|MiB|GB|KB|kB)\b",
]


def normalize_text(data, hosts=()):
    text = data.decode("utf-8", errors="replace")
    for h in hosts:
        if h:
            text = text.replace(h, "<host>")
    for pattern in TS_PATTERNS:
        text = re.sub(pattern, "<t>", text)
    return text


def gds_records(data):
    """Split a GDSII stream into (record type, payload) pairs; None if it does not parse."""
    out, i = [], 0
    while i + 4 <= len(data):
        length = int.from_bytes(data[i : i + 2], "big")
        if length < 4 or i + length > len(data):
            return None
        out.append((data[i + 2], data[i + 4 : i + length]))
        i += length
        if data[i - length + 2] == 0x04:  # ENDLIB
            break
    return out


def gds_without_timestamps(data):
    """BGNLIB (0x01) and BGNSTR (0x05) carry modification and access times; drop them."""
    recs = gds_records(data)
    if recs is None:
        return None
    return [(t, b"" if t in (0x01, 0x05) else payload) for t, payload in recs]


def is_text(data):
    return b"\0" not in data[:8192]


def classify(a, b, name, hosts=()):
    """How two differing files differ, from least to most serious."""
    if name.endswith((".gds", ".gds2", ".gdsii")):
        ga, gb = gds_without_timestamps(a), gds_without_timestamps(b)
        if ga is not None and ga == gb:
            return "timestamps", "GDS BGNLIB/BGNSTR dates only"
        if ga is not None and gb is not None and sorted(ga) == sorted(gb):
            return "ordering", "same GDS records in a different order"
        return "content", "GDS geometry or structure differs"
    if not (is_text(a) and is_text(b)):
        return "content", "binary content differs"
    na, nb = normalize_text(a, hosts), normalize_text(b, hosts)
    if na == nb:
        return "timestamps", "only timestamps, durations, memory figures or host names differ"
    la, lb = na.splitlines(), nb.splitlines()
    if sorted(la) == sorted(lb):
        return "ordering", "same lines in a different order"
    for i, (x, y) in enumerate(zip(la, lb, strict=False)):
        if x != y:
            return "content", f"line {i + 1}: {x.strip()[:100]!r} vs {y.strip()[:100]!r}"
    return "content", f"{len(la)} vs {len(lb)} lines"


SEVERITY = {"identical": 0, "timestamps": 1, "ordering": 2, "content": 3, "missing": 4}


def compare(bundle_a, run_a, bundle_b, run_b, trust_a, trust_b):
    """Verify both runs, then compare every step's subjects and byproducts."""
    rec_a, _ = verify(bundle_a, run_a, trust_a)
    rec_b, _ = verify(bundle_b, run_b, trust_b)
    meta_a = read_json(Path(bundle_a) / "openlane" / "run.json")
    meta_b = read_json(Path(bundle_b) / "openlane" / "run.json")
    hosts = (meta_a.get("host"), meta_b.get("host"))
    by_step_b = {e["step"]: s for e, s in rec_b}
    inputs = {
        "source": meta_a["source"]["digest"] == meta_b["source"]["digest"],
        "image": meta_a["image"]["digest"] == meta_b["image"]["digest"],
        "pdk": meta_a["pdk"]["digest"] == meta_b["pdk"]["digest"],
        "tools": read_json(Path(bundle_a) / "openlane" / "tools.json")
        == read_json(Path(bundle_b) / "openlane" / "tools.json"),
    }

    def files(stmt, kind):
        items = stmt["subject"] if kind == "subject" else stmt["predicate"]["runDetails"]["byproducts"]
        return {i["name"]: i["digest"]["sha256"] for i in items}

    steps, first_divergence = [], None
    for entry, sa in rec_a:
        sb = by_step_b.get(entry["step"])
        row = {"ordinal": entry["ordinal"], "step": entry["step"], "specStep": sa["predicate"]["hwFlow"]["step"]}
        for kind in ("subject", "byproduct"):
            fa = files(sa, kind)
            fb = files(sb, kind) if sb else {}
            diffs = []
            for name in sorted(set(fa) | set(fb)):
                if fa.get(name) == fb.get(name):
                    continue
                if name not in fa or name not in fb:
                    diffs.append({"name": name, "class": "missing", "detail": "only in one run"})
                    continue
                a, b = (Path(run_a) / name).read_bytes(), (Path(run_b) / name).read_bytes()
                cls, detail = classify(a, b, name, hosts)
                diffs.append({"name": name, "class": cls, "detail": detail})
            worst = max([d["class"] for d in diffs], key=SEVERITY.get, default="identical")
            row[kind + "s"] = {"total": len(set(fa) | set(fb)), "identical": len(set(fa) | set(fb)) - len(diffs)}
            row[kind + "Worst"] = worst
            row[kind + "Diffs"] = diffs
        if first_divergence is None and SEVERITY[row["subjectWorst"]] >= SEVERITY["ordering"]:
            first_divergence = entry["step"]
        steps.append(row)

    gds_a, gds_b = final_gds(rec_a)[0], final_gds(rec_b)[0]
    gds_class = "identical"
    if gds_a["digest"] != gds_b["digest"]:
        a, b = (Path(run_a) / gds_a["name"]).read_bytes(), (Path(run_b) / gds_b["name"]).read_bytes()
        gds_class, _ = classify(a, b, ".gds")
    subj_total = sum(r["subjects"]["total"] for r in steps)
    subj_same = sum(r["subjects"]["identical"] for r in steps)
    return {
        "inputsMatch": inputs,
        "finalGds": {"a": gds_a["digest"]["sha256"], "b": gds_b["digest"]["sha256"], "class": gds_class},
        "steps": len(steps),
        "stepsWithBitExactSubjects": sum(1 for r in steps if r["subjectWorst"] == "identical"),
        "subjects": {"total": subj_total, "bitExact": subj_same},
        "subjectClasses": _count(d["class"] for r in steps for d in r["subjectDiffs"]),
        "byproductClasses": _count(d["class"] for r in steps for d in r["byproductDiffs"]),
        "firstContentDivergence": first_divergence,
        "hosts": list(hosts),
        "perStep": steps,
    }


def _count(items):
    out = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return out


def markdown(report):
    r = report
    lines = [
        "## OpenLane 2 reproducibility: two runs on separate runners",
        "",
        "- Inputs identical: " + ", ".join(f"{k} {'yes' if v else 'NO'}" for k, v in r["inputsMatch"].items()),
        f"- Final GDS: **{r['finalGds']['class']}** (a `{r['finalGds']['a'][:16]}`, b `{r['finalGds']['b'][:16]}`)",
        f"- Step outputs bit-exact: {r['subjects']['bitExact']} of {r['subjects']['total']}; "
        f"steps with every output bit-exact: {r['stepsWithBitExactSubjects']} of {r['steps']}",
        f"- Differing outputs by class: {r['subjectClasses'] or 'none'}",
        f"- Differing logs and reports by class: {r['byproductClasses'] or 'none'}",
        f"- First step whose outputs differ beyond timestamps: {r['firstContentDivergence'] or 'none'}",
        "",
        "| # | OpenLane step | Spec step | Outputs bit-exact | Worst output diff | Logs, reports bit-exact | Worst |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for s in r["perStep"]:
        subj, byp = s["subjects"], s["byproducts"]
        lines.append(
            f"| {s['ordinal']} | {s['step']} | {s['specStep']} | {subj['identical']}/{subj['total']}"
            f" | {s['subjectWorst']} | {byp['identical']}/{byp['total']} | {s['byproductWorst']} |"
        )
    details = [d | {"step": s["step"]} for s in r["perStep"] for d in s["subjectDiffs"]]
    if details:
        lines += ["", "### Differing outputs", "", "| Step | File | Class | Detail |", "| --- | --- | --- | --- |"]
        for d in details:
            detail = d["detail"].replace("|", "\\|")
            lines.append(f"| {d['step']} | `{d['name']}` | {d['class']} | {detail} |")
    return "\n".join(lines) + "\n"


def rebuild_record(report, bundle_a, key, out):
    """A signed record of the second build, bound to the released GDS of the first."""
    rel_path = Path(bundle_a) / "att" / RELEASE_ATT
    final = decode(rel_path)["subject"][0]
    g = report["finalGds"]
    pred = {
        "buildDefinition": {
            "buildType": design_step_type("rebuild"),
            "externalParameters": {"comparedWith": "second OpenLane run, same inputs, separate runner"},
            "resolvedDependencies": [file_rd(rel_path, f"att/{RELEASE_ATT}")],
        },
        "runDetails": {**builder(), "byproducts": []},
        "hwFlow": {
            "step": "rebuild",
            "tools": [],
            "checks": [
                {"name": "gds-bit-exact", "result": "pass" if g["class"] == "identical" else "fail", "detail": g["b"]},
                {
                    "name": "gds-equal-ignoring-timestamps",
                    "result": "pass" if g["class"] in ("identical", "timestamps") else "fail",
                    "detail": g["class"],
                },
            ],
            "reproducibility": {k: report[k] for k in ("subjects", "subjectClasses", "firstContentDivergence")},
        },
    }
    sign(statement([final], DESIGN_FLOW, pred), load_signer(key), out)
