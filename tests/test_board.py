"""Tamper tests for the board-level example: parts[], distributor lot data and A1.

Needs the chip bundle from `e2e/run.sh produce` (HSLSA_BUNDLE, default
out/bundle). The fixture builds the board on top of it with fresh test keys,
so tests can forge validly signed records the way an insider at a
distributor, the EMS or the board owner could.
"""

import base64
import json
import os
import shutil
from pathlib import Path

import pytest

from hslsa import board, hbom
from hslsa.common import TrustRoot, VerificationError, keygen, load_signer, read_json, sha256_file, sign, write_json
from hslsa.lot import lot_digest, read_units

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "e2e" / "board"
SCENARIO, DESIGN, POLICY = HERE / "board-scenario.json", HERE / "board-design.json", HERE / "policy.json"
CHIP = Path(os.environ.get("HSLSA_BUNDLE", ROOT / "out" / "bundle"))
PRODUCED = Path(os.environ.get("HSLSA_BOARD_BUNDLE", ROOT / "out" / "board"))
ROLES = ["ems-site", "board-owner", "dist-franchised", "dist-broker", "pcb-fab"]
FLASH = "W25Q128JVSIQ"

needs_bundle = pytest.mark.skipif(not (CHIP / "att").exists(), reason="run e2e/run.sh produce first")


def decode(path):
    return json.loads(base64.b64decode(read_json(path)["payload"]))


def test_committed_board_example():
    """The committed board HBOM validates, and its subjects are reproducible from committed files."""
    example = read_json(ROOT / "hbom" / "picosoc-devboard.hbom.intoto.json")
    hbom.validate(example["predicate"])
    design, lot = example["subject"]
    assert design["digest"]["sha256"] == sha256_file(DESIGN)
    assert lot["digest"]["sha256"] == lot_digest(read_units(ROOT / "hbom" / "picosoc-devboard.board-lot.txt"))


# Schema: the level decides which manufacturing block is required.


def board_predicate():
    return {
        "hbomVersion": "0.1",
        "product": {"name": "b", "level": "board", "manufacturer": {"name": "m"}},
        "manufacturing": {"boardAssembly": {"ems": {"name": "e"}}},
        "parts": [{"manufacturer": {"name": "Winbond Electronics"}, "mpn": FLASH}],
    }


def test_schema_accepts_a_board():
    hbom.validate(board_predicate())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("parts"),
        lambda p: p["manufacturing"].pop("boardAssembly"),
        lambda p: p["product"].update(level="package"),
    ],
    ids=["board-without-parts", "board-without-assembly", "package-without-fab"],
)
def test_schema_rejects_missing_blocks(mutate):
    p = board_predicate()
    mutate(p)
    with pytest.raises(VerificationError, match="HBOM does not match its schema"):
        hbom.validate(p)


# Chain tests


def produce(work, scenario=SCENARIO):
    board.produce(work / "board", work / "chip", scenario, DESIGN, POLICY, work / "keys")


@pytest.fixture(scope="session")
def valid(tmp_path_factory):
    if not (CHIP / "att").exists():
        pytest.skip("run e2e/run.sh produce first")
    work = tmp_path_factory.mktemp("board")
    shutil.copytree(CHIP, work / "chip")
    (work / "pub").mkdir()
    for role in ROLES:
        keygen(work / "keys", role)
        shutil.copy(work / "keys" / f"{role}.pub.pem", work / "pub")
    (work / "board").mkdir()
    TrustRoot.build(work / "pub", work / "board" / "trust-root.json")
    produce(work)
    return work


@pytest.fixture
def work(valid, tmp_path):
    shutil.copytree(valid, tmp_path / "w")
    return tmp_path / "w"


def check(work, boards=None, bundle=None):
    bundle = bundle or work / "board"
    trust = TrustRoot.load(bundle / "trust-root.json")
    received = None
    if boards:
        received = work / "boards.txt"
        received.write_text("\n".join(boards) + "\n")
    return board.run(bundle, trust, POLICY, received)


def rejects(work, reason, boards=None):
    with pytest.raises(VerificationError) as err:
        check(work, boards)
    assert reason in str(err.value)


def resign(work, name, role, mutate=lambda s: None):
    path = work / "board" / "att" / name
    stmt = decode(path)
    mutate(stmt)
    sign(stmt, load_signer(work / "keys" / f"{role}.key.pem"), path)


def reseal(work, a1_mutate=lambda s: None):
    """Re-sign A1 over the current build records (an EMS insider), then the HBOM over that A1 (a trusting owner)."""
    build = board.file_rd(work / "board" / "artifacts" / board.BUILD)

    def a1(s):
        s["subject"] = [x if x["name"] != board.BUILD else build for x in s["subject"]]
        a1_mutate(s)

    resign(work, board.A1, "ems-site", a1)
    new = board.ref(work / "board", f"att/{board.A1}")
    resign(
        work,
        board.BOARD_HBOM,
        "board-owner",
        lambda s: s["predicate"]["manufacturing"]["boardAssembly"].update(attestationRef=new),
    )


def edit_scenario(work, mutate):
    sc = read_json(SCENARIO)
    mutate(sc)
    path = work / "scenario.json"
    write_json(path, sc)
    return path


def part(stmt, mpn):
    return next(p for p in stmt["predicate"]["parts"] if p["mpn"] == mpn)


def edit_builds(work, mutate):
    path = work / "board" / "artifacts" / board.BUILD
    builds = read_json(path)
    mutate(builds)
    write_json(path, builds)
    reseal(work)


@pytest.mark.skipif(not (PRODUCED / "att").exists(), reason="run e2e/board/run.sh produce first")
def test_produced_board_bundle_verifies_as_is():
    check(None, bundle=PRODUCED)


@needs_bundle
def test_rebuilt_board_verifies(work):
    result = check(work, ["DEVB-A-0001", "DEVB-A-0005"])
    assert result["lot"]["name"] == "urn:hslsa:lot:BRD-EXAMPLE-01"


# Files swapped after signing


@needs_bundle
@pytest.mark.parametrize(
    "artifact",
    [board.DESIGN, board.BUILD, "shipment-EXAMPLE-SHIP-0001.json", "shipment-EXAMPLE-SHIP-0002.json"],
)
def test_modified_artifact(work, artifact):
    with open(work / "board" / "artifacts" / artifact, "ab") as f:
        f.write(b"\n")
    rejects(work, f"subject {artifact} does not match its attested digest")


@needs_bundle
def test_board_added_to_lot(work):
    with open(work / "board" / "artifacts" / board.BOARD_LOT, "a") as f:
        f.write("DEVB-A-9999\n")
    rejects(work, "board lot list does not match the attested lot digest")


@needs_bundle
def test_received_board_failed_test(work):
    rejects(work, "received board DEVB-A-0004 is not in the board lot", boards=["DEVB-A-0001", "DEVB-A-0004"])


# Signatures


@needs_bundle
def test_a1_signed_by_board_owner(work):
    resign(work, board.A1, "board-owner")
    rejects(work, "no valid signature from role 'ems-site'")


@needs_bundle
def test_shipment_signed_by_the_broker(work):
    """A broker cannot pass its shipment off as the franchised distributor's."""
    resign(work, board.ship_att("EXAMPLE-SHIP-0001"), "dist-broker")
    rejects(work, "no valid signature from role 'dist-franchised'")


@needs_bundle
def test_chip_chain_broken_under_the_board(work):
    path = work / "board" / "parts" / "picosoc" / "att" / "mfg-f4-final-test.intoto.json"
    env = read_json(path)
    stmt = json.loads(base64.b64decode(env["payload"]))
    stmt["predicate"]["hwMfg"]["yield"]["failed"] = []
    env["payload"] = base64.b64encode(json.dumps(stmt).encode()).decode()
    write_json(path, env)
    rejects(work, "PSOC130-QFN64 lot receipt check failed: mfg-f4-final-test.intoto.json: no valid signature")


# Distributor lot data


@needs_bundle
def test_hbom_part_lot_swapped(work):
    resign(work, board.BOARD_HBOM, "board-owner", lambda s: part(s, FLASH).update(lot="EXAMPLE-WB-LOT-0666"))
    rejects(work, f"parts: {FLASH} lot EXAMPLE-WB-LOT-0666 does not match the distributor's shipment")


@needs_bundle
def test_hbom_date_code_changed(work):
    resign(work, board.BOARD_HBOM, "board-owner", lambda s: part(s, FLASH).update(dateCode="EXAMPLE-2601"))
    rejects(work, f"parts: {FLASH} lot EXAMPLE-WB-LOT-0001 does not match the distributor's shipment")


@needs_bundle
def test_part_from_a_broker(work):
    """Flash bought from a broker: the producer marks it unauthorized, and policy requires the authorized channel."""

    def via_broker(sc):
        ship = sc["shipments"][0]
        line = next(ln for ln in ship["lines"] if ln["mpn"] == FLASH)
        ship["lines"].remove(line)
        sc["shipments"].append(
            {
                "id": "EXAMPLE-SHIP-0003",
                "shipper": {"name": "Example Components Broker", "country": "US"},
                "shipDate": "2026-09-16",
                "lines": [line],
            }
        )

    produce(work, edit_scenario(work, via_broker))
    rejects(work, f"policy requires an authorized channel, and {FLASH} lot EXAMPLE-WB-LOT-0001 was not bought")
    resign(work, board.BOARD_HBOM, "board-owner", lambda s: part(s, FLASH).update(authorized=True))
    rejects(work, "Example Components Broker is not an authorized channel for Winbond Electronics")


@needs_bundle
def test_more_parts_placed_than_shipped(work):
    def short(sc):
        next(ln for ln in sc["shipments"][0]["lines"] if ln["mpn"] == FLASH)["quantity"] = 4

    produce(work, edit_scenario(work, short))
    rejects(work, f"more {FLASH} lot EXAMPLE-WB-LOT-0001 placed than were shipped")


# The chip on the board


@needs_bundle
def test_board_claims_a_chip_lot_it_did_not_receive(work):
    def other_lot(sc):
        sc["shipments"][0]["lines"][0]["lot"] = "ASM-EXAMPLE-99"

    produce(work, edit_scenario(work, other_lot))
    rejects(work, "board claims PSOC130-QFN64 lot ASM-EXAMPLE-99, but its HBOM names urn:hslsa:lot:ASM-EXAMPLE-17")


@needs_bundle
def test_scrapped_chip_shipped_to_the_ems(work, monkeypatch):
    """PSOC130-A0-00007 failed final test. The EMS's own receipt check refuses it; skipping that check does not help."""

    def scrapped(sc):
        sc["shipments"][0]["lines"][0]["units"][-1] = "PSOC130-A0-00007"

    scenario = edit_scenario(work, scrapped)
    with pytest.raises(VerificationError, match="PSOC130-A0-00007 is not in the shipped lot"):
        produce(work, scenario)
    real_check = board.chip_check
    monkeypatch.setattr(board, "chip_check", lambda chip, units: real_check(chip, None))
    produce(work, scenario)
    monkeypatch.undo()
    rejects(work, "PSOC130-QFN64 lot receipt check failed: received unit PSOC130-A0-00007 is not in the shipped lot")


@needs_bundle
def test_chip_placed_that_was_never_shipped(work):
    edit_builds(work, lambda b: b["DEVB-A-0002"]["placements"]["U1"].update(unit="PSOC130-A0-00010"))
    rejects(work, "board DEVB-A-0002 U1 unit PSOC130-A0-00010 was never shipped to the EMS")


@needs_bundle
def test_chip_placed_on_two_boards(work):
    edit_builds(work, lambda b: b["DEVB-A-0002"]["placements"]["U1"].update(unit="PSOC130-A0-00001"))
    rejects(work, "unit PSOC130-A0-00001 is placed on more than one board")


@needs_bundle
def test_part_placed_from_an_unlisted_lot(work):
    edit_builds(work, lambda b: b["DEVB-A-0003"]["placements"]["U2"].update(lot="EXAMPLE-WB-LOT-0999"))
    rejects(work, f"board DEVB-A-0003 U2 is {FLASH} lot EXAMPLE-WB-LOT-0999, which the HBOM does not list")


@needs_bundle
def test_hbom_hbomref_to_another_hbom(work):
    """Pointing the chip at a different HBOM breaks its digest."""
    resign(
        work,
        board.BOARD_HBOM,
        "board-owner",
        lambda s: part(s, "PSOC130-QFN64")["hbomRef"]["digest"].update(sha256="3" * 64),
    )
    rejects(work, "PSOC130-QFN64 hbomRef does not match its digest")


# A1 and the board HBOM


@needs_bundle
def test_a1_not_linked_to_a_shipment(work):
    def unlink(s):
        deps = s["predicate"]["buildDefinition"]["resolvedDependencies"]
        s["predicate"]["buildDefinition"]["resolvedDependencies"] = [d for d in deps if "distribution" not in d["name"]]

    reseal(work, unlink)
    rejects(work, "chain broken, resolvedDependencies do not include shipment record")


@needs_bundle
def test_a1_yield_hides_a_failed_board(work):
    reseal(work, lambda s: s["predicate"]["hwMfg"]["yield"].update(failed=[]))
    rejects(work, "yield record does not account for every board built")


@needs_bundle
def test_a1_names_another_board_design(work):
    reseal(work, lambda s: s["predicate"]["hwMfg"]["designRef"]["digest"].update(sha256="4" * 64))
    rejects(work, "designRef names a different board design")


@needs_bundle
def test_board_hbom_names_another_lot(work):
    resign(work, board.BOARD_HBOM, "board-owner", lambda s: s["subject"][1]["digest"].update(sha256="2" * 64))
    rejects(work, "lot subject does not match the A1 board lot")


@needs_bundle
def test_board_hbom_omits_a_part(work):
    def drop(s):
        s["predicate"]["parts"] = [p for p in s["predicate"]["parts"] if p["mpn"] != "RC0402FR-0710KL"]

    resign(work, board.BOARD_HBOM, "board-owner", drop)
    rejects(work, "board design R1 (RC0402FR-0710KL) has no matching part in the HBOM")
