"""The buyer's check: walk the chain by digest, then emit a signed SLSA VSA.

Implements the tapeout check and the lot receipt check from the spec section
"Where the chain is checked". Any failure raises VerificationError naming the
first broken link; nothing is emitted unless every check passes.
"""

import base64
import json
from pathlib import Path

from google.protobuf import json_format
from in_toto_attestation.predicates.provenance.v1 import provenance_pb2

from . import hbom as hbom_mod
from .common import (
    DESIGN_FLOW,
    HBOM,
    MFG_STEP,
    VSA,
    VerificationError,
    design_step_type,
    file_rd,
    load_signer,
    mfg_step_type,
    now,
    read_json,
    sha256_file,
    sign,
    statement,
)
from .design import att_name
from .lot import lot_digest, read_units
from .mfg import ATT, SIGNER

VERIFIER_ID = "https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1"


def fail(msg):
    raise VerificationError(msg)


def env_rd(bundle, name):
    return file_rd(Path(bundle) / "att" / name, f"att/{name}")


def digests(rds):
    return {d["digest"].get("sha256") for d in rds}


def require_link(stmt, label, wanted, what):
    deps = stmt["predicate"]["buildDefinition"]["resolvedDependencies"]
    missing = [w["name"] for w in wanted if w["digest"]["sha256"] not in digests(deps)]
    if missing:
        fail(f"{label}: chain broken, resolvedDependencies do not include {what} {', '.join(missing)}")


def require_gates(stmt, label, block):
    failed = [c["name"] for c in stmt["predicate"][block]["checks"] if c["result"] != "pass"]
    if failed:
        fail(f"{label}: gate failed: {', '.join(failed)}")


def require_files(bundle, stmt, label):
    """Every file subject must be present in the bundle with the attested digest."""
    for s in stmt["subject"]:
        if s["name"].startswith("urn:"):
            continue
        path = Path(bundle) / "artifacts" / s["name"]
        if not path.exists():
            fail(f"{label}: subject {s['name']} is missing from the bundle")
        if sha256_file(path) != s["digest"]["sha256"]:
            fail(f"{label}: subject {s['name']} does not match its attested digest")


def as_slsa_provenance(stmt, label):
    """The step predicates are supersets of SLSA Provenance v1: parse them with the reference schema."""
    pb = provenance_pb2.Provenance()
    try:
        json_format.ParseDict(stmt["predicate"], pb, ignore_unknown_fields=True)
    except json_format.ParseError as e:
        fail(f"{label}: not a valid SLSA Provenance v1 superset: {e}")
    if not pb.build_definition.build_type or not pb.run_details.builder.id:
        fail(f"{label}: SLSA Provenance v1 needs buildType and builder.id")


def tapeout_check(bundle, trust, policy, release=True):
    bundle = Path(bundle)
    pol = policy["design"]
    stmts = {}
    for step in pol["requiredSteps"]:
        label = f"design {step}"
        stmt = trust.open(bundle / "att" / att_name(step), "flow-platform", DESIGN_FLOW)
        if stmt["predicate"]["buildDefinition"]["buildType"] != design_step_type(step):
            fail(f"{label}: wrong buildType {stmt['predicate']['buildDefinition']['buildType']}")
        as_slsa_provenance(stmt, label)
        require_gates(stmt, label, "hwFlow")
        require_files(bundle, stmt, label)
        for t in stmt["predicate"]["hwFlow"]["tools"]:
            if t["name"] not in pol["allowedTools"]:
                fail(f"{label}: tool {t['name']} is not on the approved list")
        for consumed in pol["consumes"].get(step, []):
            require_link(stmt, label, stmts[consumed]["subject"], f"{consumed} subject")
        stmts[step] = stmt
    if not release:
        return None

    label = "design release"
    rel = trust.open(bundle / "att" / att_name("release"), "tapeout-authority", DESIGN_FLOW)
    if rel["predicate"]["buildDefinition"]["buildType"] != design_step_type("release"):
        fail(f"{label}: wrong buildType")
    as_slsa_provenance(rel, label)
    require_gates(rel, label, "hwFlow")
    require_files(bundle, rel, label)
    step_envs = [env_rd(bundle, att_name(s)) for s in pol["requiredSteps"]]
    require_link(rel, label, step_envs, "step attestation")
    final = rel["subject"][0]
    producer = stmts[pol["finalArtifactFrom"]]
    if final["digest"]["sha256"] not in digests(producer["subject"]):
        fail(f"{label}: released artifact is not an output of {pol['finalArtifactFrom']}")
    return {"final": final, "release": env_rd(bundle, att_name("release")), "inputs": step_envs}


def lot_check(bundle, trust, policy, design, units=None):
    bundle = Path(bundle)
    art = bundle / "artifacts"
    stmts, prev = {}, design["release"]
    for step in ["wafer-fab", "wafer-sort", "packaging", "final-test"]:
        label = step
        stmt = trust.open(bundle / "att" / ATT[step], SIGNER[step], MFG_STEP)
        if stmt["predicate"]["buildDefinition"]["buildType"] != mfg_step_type(step):
            fail(f"{label}: wrong buildType")
        as_slsa_provenance(stmt, label)
        require_gates(stmt, label, "hwMfg")
        require_files(bundle, stmt, label)
        require_link(stmt, label, [prev], "previous step")
        ref = stmt["predicate"]["hwMfg"]["designRef"]
        if ref["digest"] != design["final"]["digest"] or ref["release"]["digest"] != design["release"]["digest"]:
            fail(f"{label}: designRef names a different design release")
        stmts[step], prev = stmt, env_rd(bundle, ATT[step])

    # Genealogy: every packaged unit came from a passing die of this wafer lot, each die used once.
    wafer_lot = stmts["wafer-fab"]["subject"][0]
    maps = read_json(art / "wafer-maps.json")
    if maps["waferLot"] != wafer_lot["name"]:
        fail("wafer-sort: wafer maps name a different wafer lot")
    good = {(d["wafer"], d["x"], d["y"]) for d in maps["dies"] if d["bin"] == "pass"}
    genealogy = read_json(art / "genealogy.json")
    used = set()
    for unit, g in genealogy.items():
        die = (g["wafer"], g["x"], g["y"])
        if g["waferLot"] != wafer_lot["name"] or die not in good or die in used:
            fail(f"packaging: genealogy for {unit} does not trace to a unique passing die")
        used.add(die)

    packaged_rd = stmts["packaging"]["subject"][0]
    packaged = read_units(art / "packaged-lot.txt")
    if lot_digest(packaged) != packaged_rd["digest"]["sha256"] or set(packaged) != set(genealogy):
        fail("packaging: packaged lot list does not match the attested lot digest and genealogy")

    lot_rd = stmts["final-test"]["subject"][0]
    shipped = read_units(art / "shipped-lot.txt")
    if lot_digest(shipped) != lot_rd["digest"]["sha256"]:
        fail("final-test: shipped lot list does not match the attested lot digest")
    if not set(shipped) <= set(packaged):
        fail("final-test: shipped lot contains units that were never packaged")
    yld = stmts["final-test"]["predicate"]["hwMfg"]["yield"]
    if sorted(set(packaged) - set(shipped)) != sorted(yld["failed"]) or yld["passed"] != len(shipped):
        fail("final-test: yield record does not account for every packaged unit")

    # HBOM: signed by the product owner, bound to the same GDS and lot, pointing at these records.
    label = "hbom"
    hb = trust.open(bundle / "att" / "hbom.intoto.json", "product-owner", HBOM)
    hbom_mod.validate(hb["predicate"])
    subj = {s["name"]: s["digest"] for s in hb["subject"]}
    if subj.get(design["final"]["name"]) != design["final"]["digest"]:
        fail(f"{label}: design subject does not match the released design")
    if subj.get(lot_rd["name"]) != lot_rd["digest"]:
        fail(f"{label}: lot subject does not match the final test shipped lot")
    m = hb["predicate"]["manufacturing"]
    refs = [
        (m["fab"]["attestationRef"], "wafer-fab"),
        (m["assembly"]["attestationRef"], "packaging"),
        (m["test"][0]["resultsRef"], "wafer-sort"),
        (m["test"][1]["resultsRef"], "final-test"),
    ]
    refs += [(f["provenanceRef"], None) for f in hb["predicate"]["design"]["flow"]]
    for ref, step in refs:
        name = ref["uri"].removeprefix("file:att/")
        if step and name != ATT[step]:
            fail(f"{label}: reference for {step} points at {name}")
        if file_rd(bundle / "att" / name)["digest"] != ref["digest"]:
            fail(f"{label}: reference to {name} does not match its digest")

    for unit in units or []:
        if unit not in shipped:
            fail(f"received unit {unit} is not in the shipped lot")
    return {"lot": lot_rd, "inputs": [env_rd(bundle, ATT[s]) for s in ATT] + [env_rd(bundle, "hbom.intoto.json")]}


def vsa(subject, resource_uri, levels, inputs, policy_path, key, out):
    predicate = {
        "verifier": {"id": VERIFIER_ID},
        "timeVerified": now(),
        "resourceUri": resource_uri,
        "policy": {"uri": f"file:{Path(policy_path).name}", "digest": {"sha256": sha256_file(policy_path)}},
        "inputAttestations": [{"uri": f"file:{i['name']}", "digest": i["digest"]} for i in inputs],
        "verificationResult": "PASSED",
        "verifiedLevels": levels,
    }
    sign(statement([subject], VSA, predicate), load_signer(key), out)


def run(bundle, trust, policy_path, units_path=None, vsa_key=None, vsa_dir=None):
    policy = read_json(policy_path)
    design = tapeout_check(bundle, trust, policy)
    print(f"tapeout check: PASSED for {design['final']['name']} sha256:{design['final']['digest']['sha256']}")
    units = read_units(units_path) if units_path else None
    lot = lot_check(bundle, trust, policy, design, units)
    print(
        f"lot receipt check: PASSED for {lot['lot']['name']} sha256:{lot['lot']['digest']['sha256']}"
        + (f", {len(units)} received units found in the lot" if units else "")
    )
    if vsa_key:
        out = Path(vsa_dir)
        claims = policy["claims"]
        vsa(
            design["final"],
            f"hslsa:design:{design['final']['name']}",
            claims["design"],
            [design["release"]] + design["inputs"],
            policy_path,
            vsa_key,
            out / "design.vsa.intoto.json",
        )
        vsa(
            lot["lot"],
            lot["lot"]["name"],
            claims["lot"],
            lot["inputs"] + [design["release"]],
            policy_path,
            vsa_key,
            out / "lot.vsa.intoto.json",
        )
        print(f"VSAs written to {out}: design {claims['design']}, lot {claims['lot']}")
    return design, lot


def decode(path):
    return json.loads(base64.b64decode(read_json(path)["payload"]))
