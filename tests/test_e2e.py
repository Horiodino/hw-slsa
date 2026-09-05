"""Tamper tests: every broken link in the chain must fail verification, for the right reason.

Needs a bundle from `e2e/run.sh produce` (HSLSA_BUNDLE, default out/bundle).
The producer keys never leave the produce job, so the fixture re-signs the
bundle's design records with fresh test keys and rebuilds the rest of the
chain on top of them. Tests can then forge records that carry valid
signatures and check that the verifier still catches the lie.
"""

import base64
import json
import os
import shutil
from pathlib import Path

import pytest

from hslsa import design, hbom, mfg, verify
from hslsa.common import TrustRoot, VerificationError, keygen, load_signer, read_json, sign, write_json
from hslsa.lot import lot_digest, read_units

ROOT = Path(__file__).resolve().parents[1]
E2E = ROOT / "e2e" / "picorv32"
LOCK, SCENARIO, POLICY = E2E / "inputs.lock.json", E2E / "mfg-scenario.json", E2E / "policy.json"
SOURCE = Path(os.environ.get("HSLSA_BUNDLE", ROOT / "out" / "bundle"))
ROLES = ["flow-platform", "tapeout-authority", "fab-site", "sort-site", "osat-site", "test-site", "product-owner"]


def test_lot_digest_matches_spec_example():
    """The committed example's lot subject is reproducible from its unit list."""
    example = read_json(ROOT / "hbom" / "picosoc-sky130.hbom.intoto.json")
    lot = next(s for s in example["subject"] if s["name"].startswith("urn:hslsa:lot:"))
    units = read_units(ROOT / "hbom" / "picosoc-sky130.shipped-lot.txt")
    assert lot_digest(units) == lot["digest"]["sha256"]


def test_lot_digest_is_order_independent_and_rejects_duplicates():
    assert lot_digest(["b", "a"]) == lot_digest(["a", "b"])
    with pytest.raises(ValueError):
        lot_digest(["a", "a"])


needs_bundle = pytest.mark.skipif(not (SOURCE / "att").exists(), reason="run e2e/run.sh produce first")


def decode(path):
    return json.loads(base64.b64decode(read_json(path)["payload"]))


def resign(bundle, name, role, mutate=lambda s: None):
    path = bundle / "att" / name
    stmt = decode(path)
    mutate(stmt)
    sign(stmt, load_signer(bundle.parent / "keys" / f"{role}.key.pem"), path)


def rebuild_downstream(bundle, from_release=True):
    keys = bundle.parent / "keys"
    if from_release:
        design.release(bundle, LOCK, keys / "tapeout-authority.key.pem", bundle / "trust-root.json", POLICY)
    mfg.run(bundle, SCENARIO, keys)
    hbom.build(bundle, LOCK, SCENARIO, keys / "product-owner.key.pem")


@pytest.fixture(scope="session")
def valid(tmp_path_factory):
    work = tmp_path_factory.mktemp("valid")
    bundle = work / "bundle"
    shutil.copytree(SOURCE, bundle)
    keygen(work / "keys", "attacker")
    (work / "pub").mkdir()
    for role in ROLES:
        keygen(work / "keys", role)
        shutil.copy(work / "keys" / f"{role}.pub.pem", work / "pub")
    TrustRoot.build(work / "pub", bundle / "trust-root.json")
    for step in design.STEPS:
        resign(bundle, design.att_name(step), "flow-platform")
    rebuild_downstream(bundle)
    return work


@pytest.fixture
def bundle(valid, tmp_path):
    shutil.copytree(valid, tmp_path / "w")
    return tmp_path / "w" / "bundle"


def check(bundle, units=None):
    trust = TrustRoot.load(bundle / "trust-root.json")
    units_file = None
    if units:
        units_file = bundle.parent / "units.txt"
        units_file.write_text("\n".join(units) + "\n")
    return verify.run(bundle, trust, POLICY, units_file)


def rejects(bundle, reason, units=None):
    with pytest.raises(VerificationError) as err:
        check(bundle, units)
    assert reason in str(err.value)


@needs_bundle
def test_produced_bundle_verifies_as_is():
    check(SOURCE, read_units(E2E / "received-units.txt"))


@needs_bundle
def test_rebuilt_bundle_verifies(bundle):
    check(bundle, read_units(E2E / "received-units.txt"))


# Files swapped after signing


@needs_bundle
@pytest.mark.parametrize(
    "artifact",
    ["picorv32.netlist.v", "source.tar", "simulation.log", "wafer-maps.json", "genealogy.json"],
)
def test_modified_artifact(bundle, artifact):
    with open(bundle / "artifacts" / artifact, "ab") as f:
        f.write(b"\n")
    rejects(bundle, f"subject {artifact} does not match its attested digest")


@needs_bundle
def test_unit_added_to_shipped_lot(bundle):
    with open(bundle / "artifacts" / "shipped-lot.txt", "a") as f:
        f.write("PSOC130-A0-99999\n")
    rejects(bundle, "shipped lot list does not match the attested lot digest")


@needs_bundle
def test_received_unit_not_in_lot(bundle):
    rejects(bundle, "PSOC130-A0-00007 is not in the shipped lot", units=["PSOC130-A0-00001", "PSOC130-A0-00007"])


# Signatures


@needs_bundle
def test_missing_step(bundle):
    (bundle / "att" / design.att_name("simulation")).unlink()
    rejects(bundle, "missing attestation")


@needs_bundle
def test_payload_edited_without_resigning(bundle):
    path = bundle / "att" / mfg.ATT["final-test"]
    env = read_json(path)
    stmt = json.loads(base64.b64decode(env["payload"]))
    stmt["predicate"]["hwMfg"]["yield"]["failed"] = []
    env["payload"] = base64.b64encode(json.dumps(stmt).encode()).decode()
    write_json(path, env)
    rejects(bundle, "no valid signature from role 'test-site'")


@needs_bundle
def test_step_signed_by_unknown_key(bundle):
    resign(bundle, design.att_name("synthesis"), "attacker")
    rejects(bundle, "no valid signature from role 'flow-platform'")


@needs_bundle
def test_release_signed_by_flow_platform(bundle):
    """Separation of duties: the flow platform cannot release its own output."""
    resign(bundle, design.att_name("release"), "flow-platform")
    rejects(bundle, "no valid signature from role 'tapeout-authority'")


@needs_bundle
def test_record_from_the_wrong_site(bundle):
    shutil.copy(bundle / "att" / mfg.ATT["wafer-sort"], bundle / "att" / mfg.ATT["wafer-fab"])
    rejects(bundle, "no valid signature from role 'fab-site'")


# Validly signed records that lie


@needs_bundle
def test_failed_gate(bundle):
    def fail_sim(s):
        s["predicate"]["hwFlow"]["checks"][1]["result"] = "fail"

    resign(bundle, design.att_name("simulation"), "flow-platform", fail_sim)
    rejects(bundle, "design simulation: gate failed: testbench-finished")


@needs_bundle
def test_unapproved_tool(bundle):
    def swap_tool(s):
        s["predicate"]["hwFlow"]["tools"][0]["name"] = "yosys-patched"

    resign(bundle, design.att_name("synthesis"), "flow-platform", swap_tool)
    rejects(bundle, "tool yosys-patched is not on the approved list")


@needs_bundle
def test_step_not_linked_to_source(bundle):
    def unlink(s):
        s["predicate"]["buildDefinition"]["resolvedDependencies"] = []

    resign(bundle, design.att_name("synthesis"), "flow-platform", unlink)
    rejects(bundle, "design synthesis: chain broken")


@needs_bundle
def test_release_of_an_artifact_the_flow_did_not_build(bundle):
    def other(s):
        s["subject"][0]["digest"]["sha256"] = "0" * 64

    resign(bundle, design.att_name("release"), "tapeout-authority", other)
    rejects(bundle, "subject picorv32.netlist.v does not match its attested digest")


@needs_bundle
def test_mfg_step_names_another_design(bundle):
    def other(s):
        s["predicate"]["hwMfg"]["designRef"]["digest"]["sha256"] = "1" * 64

    resign(bundle, mfg.ATT["packaging"], "osat-site", other)
    rejects(bundle, "packaging: designRef names a different design release")


@needs_bundle
def test_yield_does_not_reconcile(bundle):
    def hide_failure(s):
        s["predicate"]["hwMfg"]["yield"]["failed"] = s["predicate"]["hwMfg"]["yield"]["failed"][1:]

    resign(bundle, mfg.ATT["final-test"], "test-site", hide_failure)
    rejects(bundle, "yield record does not account for every packaged unit")


@needs_bundle
def test_hbom_names_another_lot(bundle):
    def other(s):
        s["subject"][1]["digest"]["sha256"] = "2" * 64

    resign(bundle, "hbom.intoto.json", "product-owner", other)
    rejects(bundle, "hbom: lot subject does not match the final test shipped lot")


@needs_bundle
def test_hbom_must_match_schema(bundle):
    def bad(s):
        s["predicate"]["product"]["level"] = "wafer"

    resign(bundle, "hbom.intoto.json", "product-owner", bad)
    rejects(bundle, "HBOM does not match its schema")
