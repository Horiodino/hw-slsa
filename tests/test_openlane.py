"""OpenLane step records: chain checks and the reproducibility classifier, on a synthetic run.

No OpenLane needed: the fixture lays out step directories the way OpenLane 2
writes them (state_in.json, state_out.json, config.json, runtime.txt) and
signs them with the same code the real run uses.
"""

import json
import shutil
from pathlib import Path

import pytest

from hslsa import design, openlane
from hslsa.common import TrustRoot, VerificationError, keygen, load_signer, read_json, sign, write_json
from hslsa.design import deterministic_tar

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "openlane2" / "spm" / "flow.lock.json"


def gds(stamp, geometry=b"\x00\x01"):
    def rec(rtype, dtype, payload):
        return (4 + len(payload)).to_bytes(2, "big") + bytes([rtype, dtype]) + payload

    dates = b"".join(x.to_bytes(2, "big") for x in [2026, 9, 29, 8, 30, stamp] * 2)
    return b"".join(
        [
            rec(0x00, 0x02, (600).to_bytes(2, "big")),
            rec(0x01, 0x02, dates),
            rec(0x02, 0x06, b"spm\x00"),
            rec(0x05, 0x02, dates),
            rec(0x06, 0x06, b"spm\x00"),
            rec(0x10, 0x03, geometry * 4),
            rec(0x07, 0x00, b""),
            rec(0x04, 0x00, b""),
        ]
    )


# (slug, views produced, metrics produced)
STEPS = [
    ("yosys-synthesis", {"nl": "spm.nl.v"}, {"design__instance__count": 100}),
    ("openroad-floorplan", {"odb": "spm.odb", "def": "spm.def"}, {}),
    ("openroad-globalplacement", {"odb": "spm.odb"}, {"timing__setup__ws": float("inf")}),
    ("openroad-detailedrouting", {"odb": "spm.odb", "def": "spm.def"}, {"route__drc_errors": 0}),
    ("openroad-rcx", {"spef.nom_*": "spm.nom.spef"}, {}),
    ("magic-streamout", {"gds": "spm.gds"}, {}),
    ("magic-drc", {}, {"magic__drc_error__count": 0}),
    ("netgen-lvs", {}, {"design__lvs_error__count": 0}),
]


def fake_run(flow, stamp=0, tweak=None):
    """Write the step directories one by one, signing each as the watcher would."""
    state = {"metrics": {}}
    for i, (slug, produced, metrics) in enumerate(STEPS, 1):
        d = flow.run_dir / f"{i:02d}-{slug}"
        d.mkdir(parents=True)
        (d / "state_in.json").write_text(json.dumps(state))
        (d / "config.json").write_text(json.dumps({"DESIGN_NAME": "spm", "step": slug}))
        out = json.loads(json.dumps(state))
        for view, name in produced.items():
            if name.endswith(".gds"):
                data = gds(stamp)
            else:
                data = f"{slug} {view} generated 2026-09-29 08:30:{stamp:02d}\n".encode()
            if tweak and tweak[0] == slug:
                data = tweak[1](data)
            (d / name).write_bytes(data)
            if "." in view:
                top, key = view.split(".")
                out.setdefault(top, {})[key] = str(d / name)
            else:
                out[view] = str(d / name)
        out["metrics"].update(metrics)
        (d / "state_out.json").write_text(json.dumps(out))
        (d / f"{slug}.log").write_text(f"[08:30:{stamp:02d}] ran {slug}\n")
        (d / "runtime.txt").write_text("0:00:01")
        flow.attest_ready()
        state = out
    flow.write_summary(0)


def produce(base, stamp=0, tweak=None):
    """A signed bundle for a synthetic run under base."""
    keys, bundle, work = base / "keys", base / "bundle", base / "work"
    keygen(keys, "flow-platform")
    keygen(keys, "tapeout-authority")
    (keys / "pub").mkdir()
    for role in ["flow-platform", "tapeout-authority"]:
        shutil.copy(keys / f"{role}.pub.pem", keys / "pub")
    TrustRoot.build(keys / "pub", bundle / "trust-root.json")

    lock = read_json(LOCK)
    cache = base / "cache"
    for name in lock["source"]["files"]:
        (cache / name).parent.mkdir(parents=True, exist_ok=True)
        (cache / name).write_text(f"source {name}\n")
    lock["source"]["files"] = {n: openlane.sha256_file(cache / n) for n in lock["source"]["files"]}
    write_json(base / "lock.json", lock)
    design.source_freeze(bundle, base / "lock.json", keys / "flow-platform.key.pem", cache)

    flow = openlane.Flow(bundle, base / "lock.json", keys / "flow-platform.key.pem", work, base)
    flow.meta.mkdir(parents=True)
    flow.source = openlane.file_rd(bundle / "artifacts" / "source.tar") | {"annotations": {"kind": "source"}}
    flow.tools = {
        "openlane": {"version": "2.3.10", "digest": "aa" * 32},
        "yosys": {"version": "0.4", "digest": "bb" * 32},
    }
    write_json(flow.meta / "tools.json", flow.tools)
    flow.pdk = {"name": "sky130A", "digest": {"sha256": "cc" * 32}, "annotations": {"kind": "pdk"}}
    flow.common_deps = [flow.source, flow.image_rd() | {"annotations": {"kind": "toolchain"}}, flow.pdk]
    fake_run(flow, stamp, tweak)
    openlane.release(bundle, flow.run_dir, keys / "tapeout-authority.key.pem", bundle / "trust-root.json", LOCK)
    return bundle, flow.run_dir, keys


@pytest.fixture
def run(tmp_path):
    bundle, run_dir, keys = produce(tmp_path)
    return bundle, run_dir, keys, TrustRoot.load(bundle / "trust-root.json")


def resign(bundle, keys, name, mutate, role="flow-platform"):
    path = bundle / "att" / name
    stmt = openlane.decode(path)
    mutate(stmt)
    sign(stmt, load_signer(keys / f"{role}.key.pem"), path)


def entries(bundle):
    return read_json(bundle / "openlane" / "run.json")["steps"]


def test_valid_run_verifies(run):
    bundle, run_dir, _, trust = run
    records, final = openlane.verify(bundle, run_dir, trust)
    assert len(records) == len(STEPS)
    assert final["name"] == "spm.gds"
    steps = [s["predicate"]["hwFlow"]["step"] for _, s in records]
    assert steps == ["synthesis", "floorplan", "place-cts", "routing", "signoff", "gds-stream-out"] + ["signoff"] * 2
    # inf metrics are carried as strings, and views link to the step that produced them
    assert records[2][1]["predicate"]["hwFlow"]["metrics"]["timing__setup__ws"] == "inf"
    deps = records[3][1]["predicate"]["buildDefinition"]["resolvedDependencies"]
    assert {d["name"] for d in deps if d["annotations"]["kind"] == "view"} == {
        "01-yosys-synthesis/spm.nl.v",
        "03-openroad-globalplacement/spm.odb",
        "02-openroad-floorplan/spm.def",
    }


def test_changed_output_is_caught(run):
    bundle, run_dir, _, trust = run
    (run_dir / "04-openroad-detailedrouting" / "spm.def").write_text("rerouted\n")
    with pytest.raises(VerificationError, match="subject 04-openroad-detailedrouting/spm.def"):
        openlane.verify(bundle, run_dir, trust)


def test_input_view_from_nowhere_is_caught(run):
    bundle, run_dir, keys, trust = run
    name = entries(bundle)[3]["attestation"]

    def swap(stmt):
        for d in stmt["predicate"]["buildDefinition"]["resolvedDependencies"]:
            if d["name"].endswith("spm.odb"):
                d["digest"]["sha256"] = "00" * 32

    resign(bundle, keys, name, swap)
    with pytest.raises(VerificationError, match="input view .* is not an output of any earlier step"):
        openlane.verify(bundle, run_dir, trust)


def test_dropped_step_is_caught(run):
    bundle, run_dir, _, trust = run
    meta = read_json(bundle / "openlane" / "run.json")
    del meta["steps"][2]
    write_json(bundle / "openlane" / "run.json", meta)
    with pytest.raises(VerificationError):
        openlane.verify(bundle, run_dir, trust)


def test_other_pdk_is_caught(run):
    bundle, run_dir, keys, trust = run

    def other_pdk(stmt):
        for d in stmt["predicate"]["buildDefinition"]["resolvedDependencies"]:
            if d.get("annotations", {}).get("kind") == "pdk":
                d["digest"]["sha256"] = "dd" * 32

    resign(bundle, keys, entries(bundle)[0]["attestation"], other_pdk)
    with pytest.raises(VerificationError, match="PDK"):
        openlane.verify(bundle, run_dir, trust)


def test_step_signed_by_wrong_role_is_caught(run):
    bundle, run_dir, keys, trust = run
    resign(bundle, keys, entries(bundle)[1]["attestation"], lambda s: None, role="tapeout-authority")
    with pytest.raises(VerificationError, match="no valid signature from role 'flow-platform'"):
        openlane.verify(bundle, run_dir, trust)


def test_release_of_other_gds_is_caught(run):
    bundle, run_dir, keys, trust = run
    (bundle / "artifacts" / "spm.gds").write_bytes(gds(9, b"\x09\x09"))

    def other(stmt):
        stmt["subject"][0]["digest"]["sha256"] = openlane.sha256_file(bundle / "artifacts" / "spm.gds")

    resign(bundle, keys, openlane.RELEASE_ATT, other, role="tapeout-authority")
    with pytest.raises(VerificationError, match="not the flow's final GDS"):
        openlane.verify(bundle, run_dir, trust)


def test_release_refuses_failed_signoff(tmp_path):
    STEPS.append(("checker-klayoutdrc", {}, {"klayout__drc_error__count": 3}))
    try:
        with pytest.raises(SystemExit, match="klayout__drc_error__count"):
            produce(tmp_path)
    finally:
        STEPS.pop()


def test_compare_identical_runs(tmp_path):
    a = produce(tmp_path / "a")
    b = produce(tmp_path / "b")
    trust = [TrustRoot.load(x[0] / "trust-root.json") for x in (a, b)]
    report = openlane.compare(a[0], a[1], b[0], b[1], *trust)
    assert report["finalGds"]["class"] == "identical"
    assert report["subjects"]["bitExact"] < report["subjects"]["total"]  # state_out.json names the run dir
    assert report["firstContentDivergence"] is not None


def test_compare_timestamps_and_content(tmp_path):
    """Runs laid out at the same path, one second apart, with one real difference in routing."""
    base = tmp_path / "same"
    a = produce(base, stamp=1)
    shutil.move(base, tmp_path / "a")
    b = produce(base, stamp=2, tweak=("openroad-detailedrouting", lambda d: d.replace(b"def", b"DEF")))
    shutil.move(base, tmp_path / "b")
    a = (tmp_path / "a" / "bundle", tmp_path / "a" / a[1].relative_to(base))
    b = (tmp_path / "b" / "bundle", tmp_path / "b" / b[1].relative_to(base))
    report = openlane.compare(a[0], a[1], b[0], b[1], *[TrustRoot.load(x[0] / "trust-root.json") for x in (a, b)])
    rows = {r["step"]: r for r in report["perStep"]}
    assert rows["yosys-synthesis"]["subjectWorst"] == "timestamps"
    assert rows["magic-streamout"]["subjectWorst"] == "timestamps"
    assert rows["openroad-detailedrouting"]["subjectWorst"] == "content"
    assert report["firstContentDivergence"] == "openroad-detailedrouting"
    assert report["finalGds"]["class"] == "timestamps"
    md = openlane.markdown(report)
    assert "openroad-detailedrouting" in md and "| content |" in md


def test_classify():
    assert openlane.classify(gds(1), gds(2), "x.gds")[0] == "timestamps"
    assert openlane.classify(gds(1), gds(1, b"\x07\x07"), "x.gds")[0] == "content"
    assert openlane.classify(b"a\nb\n", b"b\na\n", "x.rpt")[0] == "ordering"
    assert (
        openlane.classify(b"took 1.5 s on fv-az1\n", b"took 2.25 s on fv-az2\n", "x.log", ("fv-az1", "fv-az2"))[0]
        == "timestamps"
    )
    assert openlane.classify(b"\0odb1", b"\0odb2", "x.odb")[0] == "content"
    mag = b"magic\ntech sky130A\nmagscale 1 2\ntimestamp %d\n"
    assert openlane.classify(mag % 1790671539, mag % 1790671554, "spm.mag")[0] == "timestamps"


def test_spec_step_mapping_covers_classic_flow():
    classic = [
        "verilator-lint", "checker-linttimingconstructs", "yosys-jsonheader", "yosys-synthesis",
        "checker-yosysunmappedcells", "openroad-checksdcfiles", "openroad-staprepnr", "openroad-floorplan",
        "odb-setpowerconnections", "openroad-tapendcapinsertion", "openroad-generatepdn",
        "openroad-globalplacementskipio", "openroad-ioplacement", "odb-customioplacement", "openroad-globalplacement",
        "odb-writeverilogheader", "checker-powergridviolations", "openroad-stamidpnr", "openroad-cts",
        "openroad-detailedplacement", "openroad-globalrouting", "openroad-detailedrouting", "checker-trdrc",
        "odb-reportwirelength", "openroad-fillinsertion", "openroad-rcx", "openroad-stapostpnr", "magic-streamout",
        "klayout-streamout", "magic-writelef", "klayout-xor", "magic-drc", "klayout-drc", "magic-spiceextraction",
        "netgen-lvs", "checker-lvs", "misc-reportmanufacturability",
    ]  # fmt: skip
    assert [s for s in classic if openlane.spec_step(s) == "other"] == []
    assert openlane.spec_step("openroad-stamidpnr") == "signoff"
    assert openlane.spec_step("klayout-streamout") == "gds-stream-out"


def test_deterministic_tar_of_nested_source(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "f.v").write_text("module f; endmodule\n")
    deterministic_tar(tmp_path, ["a/b/f.v"], tmp_path / "1.tar")
    deterministic_tar(tmp_path, ["a/b/f.v"], tmp_path / "2.tar")
    assert (tmp_path / "1.tar").read_bytes() == (tmp_path / "2.tar").read_bytes()
