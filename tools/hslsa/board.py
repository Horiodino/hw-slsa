"""Assembly track: a board built from the example chip and off-the-shelf parts.

The board carries the PicoSoC from the chip chain plus commodity parts that
have no HBOM of their own. Every lot reaches the assembler through a signed
distribution record (a distributor, or a manufacturer shipping direct), the
EMS runs the chip's lot receipt check before placement and signs A1 against
each board serial and the chip serial placed on it, and the board owner signs
a board HBOM whose parts[] points at those records.

As with the chip, the physical data (shipments, placements, board test
results) comes from a scenario file; every signature, digest link and check
is real.
"""

import shutil
from pathlib import Path

from . import hbom as hbom_mod
from . import verify
from .common import (
    HBOM,
    MFG_STEP,
    TrustRoot,
    VerificationError,
    file_rd,
    load_signer,
    mfg_step_type,
    now,
    rd,
    read_json,
    sha256_bytes,
    sign,
    statement,
    write_json,
)
from .lot import lot_digest, read_units, write_units

A1 = "mfg-a1-board-assembly.intoto.json"
BOARD_HBOM = "hbom.intoto.json"
DESIGN = "board-design.json"
BUILD = "board-build.json"
BOARD_LOT = "board-lot.txt"
EMS_ROLE, OWNER_ROLE = "ems-site", "board-owner"


def fail(msg):
    raise VerificationError(msg)


def slug(name):
    return name.lower().replace(" ", "-")


def ship_att(shipment_id):
    return f"mfg-distribution-{shipment_id}.intoto.json"


def board_rd(manufacturer, serial):
    """Board subject: URN plus the digest of its serial (UTF-8, no newline) until boards carry an identity cert."""
    return rd(f"urn:hslsa:board:{slug(manufacturer)}:{serial}", sha256_bytes(serial.encode()))


def ref(bundle, rel):
    return {"uri": f"file:{rel}", "digest": file_rd(Path(bundle) / rel)["digest"]}


def env_rd(bundle, rel):
    return file_rd(Path(bundle) / rel, rel)


def passed(checks):
    return [{"name": c, "result": "pass"} for c in checks]


def record(bundle, step, name, subjects, external, deps, hw, key):
    pred = {
        "buildDefinition": {
            "buildType": mfg_step_type(step),
            "externalParameters": external,
            "resolvedDependencies": deps,
        },
        "runDetails": {
            "builder": {"id": f"urn:hslsa:site:{slug(hw['site']['name'])}"},
            "metadata": {"invocationId": f"{step}:{external['id']}", "finishedOn": now()},
        },
        "hwMfg": {"step": step, "confidential": [], **hw},
    }
    sign(statement(subjects, MFG_STEP, pred), load_signer(key), Path(bundle) / "att" / name)
    print(f"{step} {external['id']}: signed by {Path(key).name.removesuffix('.key.pem')}")
    return env_rd(bundle, f"att/{name}")


def chip_check(chip, units):
    """The buyer's tapeout and lot receipt check on the chip's own bundle, with its own trust root and policy."""
    trust = TrustRoot.load(chip / "trust-root.json")
    policy = read_json(chip / "policy.json")
    design = verify.tapeout_check(chip, trust, policy)
    return verify.lot_check(chip, trust, policy, design, units)


def produce(bundle, chip_bundle, scenario_path, design_path, policy_path, keys):
    bundle, keys = Path(bundle), Path(keys)
    art = bundle / "artifacts"
    sc, pol, board_design = read_json(scenario_path), read_json(policy_path), read_json(design_path)
    for sub in ("att", "artifacts", "parts"):
        shutil.rmtree(bundle / sub, ignore_errors=True)
    art.mkdir(parents=True)
    (bundle / "att").mkdir()

    # The chip vendor's bundle travels with the chips.
    chip_rel = sc["chip"]["bundle"]
    chip = bundle / chip_rel
    shutil.copytree(chip_bundle, chip)
    shutil.copy(design_path, art / DESIGN)
    design = file_rd(art / DESIGN)

    # Distribution: one signed record per shipment into the EMS.
    ships, lines = {}, {}
    for s in sc["shipments"]:
        write_json(art / f"shipment-{s['id']}.json", s)
        deps = []
        for line in s["lines"]:
            lines[line["mpn"]] = (s, line)
            if line["mpn"] == sc["chip"]["mpn"]:
                deps.append(
                    rd(f"urn:hslsa:lot:{line['lot']}", lot_digest(read_units(chip / "artifacts" / "shipped-lot.txt")))
                )
        ships[s["id"]] = record(
            bundle,
            "distribution",
            ship_att(s["id"]),
            [file_rd(art / f"shipment-{s['id']}.json")],
            {"id": s["id"], "shipDate": s["shipDate"]},
            deps,
            {"site": s["shipper"], "checks": passed(["certificate-of-conformance", "traceable-to-manufacturer"])},
            keys / f"{pol['shippers'][s['shipper']['name']]['role']}.key.pem",
        )

    # A1: the EMS checks the chip lot before placement, then builds and tests each board.
    chip_ship, chip_line = lines[sc["chip"]["mpn"]]
    chip_lot = chip_check(chip, chip_line["units"])["lot"]
    print(f"part lot receipt check: PASSED for {chip_lot['name']}, {len(chip_line['units'])} units received")
    asm, mfr = sc["assembly"], sc["product"]["manufacturer"]["name"]
    chips = iter(chip_line["units"])
    builds = {}
    for i in range(asm["boards"]):
        serial = f"{asm['serialPrefix']}{i + 1:04d}"
        placements = {}
        for item in board_design["bom"]:
            _, line = lines[item["mpn"]]
            for ref_des in item["refDes"]:
                placements[ref_des] = {"mpn": line["mpn"], "lot": line["lot"]}
                if line["mpn"] == sc["chip"]["mpn"]:
                    placements[ref_des]["unit"] = next(chips)
        builds[serial] = {"placements": placements, "result": "fail" if serial in asm["failedBoards"] else "pass"}
    write_json(art / BUILD, builds)
    boards = sorted(s for s, b in builds.items() if b["result"] == "pass")
    write_units(art / BOARD_LOT, boards)
    board_lot = rd(f"urn:hslsa:lot:{asm['boardLot']}", lot_digest(boards))
    chip_rds = [
        env_rd(bundle, f"{chip_rel}/att/{BOARD_HBOM}"),
        env_rd(bundle, f"{chip_rel}/att/mfg-f4-final-test.intoto.json"),
    ]
    a1 = record(
        bundle,
        "board-assembly",
        A1,
        [board_lot, *(board_rd(mfr, s) for s in boards), file_rd(art / BUILD)],
        {"id": asm["boardLot"], "boardDesign": DESIGN},
        [*ships.values(), *chip_rds, chip_lot, design],
        {
            "site": asm["site"],
            "designRef": {"name": design["name"], "digest": design["digest"]},
            "yield": {"in": len(builds), "passed": len(boards), "failed": sorted(asm["failedBoards"])},
            "checks": passed(["part-lot-receipt-check", "aoi", "x-ray-sample", "ict", "functional-test"]),
        },
        keys / f"{EMS_ROLE}.key.pem",
    )

    # Board HBOM: parts[] carries the distributor lot data and points at each shipment record.
    parts = []
    for item in board_design["bom"]:
        s, line = lines[item["mpn"]]
        shipper = s["shipper"]["name"]
        part = {
            "refDes": item["refDes"],
            "manufacturer": {"name": line["manufacturer"]},
            "mpn": line["mpn"],
            "dateCode": line["dateCode"],
            "lot": line["lot"],
            "distributor": s["shipper"],
            "authorized": line["manufacturer"] in pol["shippers"][shipper]["authorizedFor"],
            "distributionRef": ref(bundle, f"att/{ship_att(s['id'])}"),
        }
        if line["mpn"] == sc["chip"]["mpn"]:
            part["hbomRef"] = ref(bundle, f"{chip_rel}/att/{BOARD_HBOM}")
        parts.append(part)
    predicate = {
        "hbomVersion": "0.1",
        "product": sc["product"],
        "design": {"finalLayout": ref(bundle, f"artifacts/{DESIGN}")},
        "manufacturing": {
            "boardAssembly": {
                "ems": asm["site"],
                "boardLot": asm["boardLot"],
                "attestationRef": ref(bundle, f"att/{A1}"),
            },
        },
        "parts": parts,
    }
    hbom_mod.validate(predicate)
    sign(
        statement([design, board_lot], HBOM, predicate),
        load_signer(keys / f"{OWNER_ROLE}.key.pem"),
        bundle / "att" / BOARD_HBOM,
    )
    print(f"board hbom: signed, {len(parts)} part lines, board lot {board_lot['name']} of {len(boards)} boards")
    return a1


# The buyer's check for the board


def check(bundle, trust, policy_path, received=None):
    bundle = Path(bundle)
    art = bundle / "artifacts"
    pol = read_json(policy_path)

    label = "board hbom"
    hb = trust.open(bundle / "att" / BOARD_HBOM, OWNER_ROLE, HBOM)
    hbom_mod.validate(hb["predicate"])
    if hb["predicate"]["product"]["level"] not in ("module", "board", "system"):
        fail(f"{label}: product level is {hb['predicate']['product']['level']}, not a board")
    design_subj, lot_subj = hb["subject"]
    verify.require_files(bundle, {"subject": [design_subj]}, label)
    board_design = read_json(art / design_subj["name"])

    label = "board-assembly"
    a1 = trust.open(bundle / "att" / A1, EMS_ROLE, MFG_STEP)
    if a1["predicate"]["buildDefinition"]["buildType"] != mfg_step_type("board-assembly"):
        fail(f"{label}: wrong buildType")
    verify.as_slsa_provenance(a1, label)
    verify.require_gates(a1, label, "hwMfg")
    verify.require_files(bundle, a1, label)
    hw = a1["predicate"]["hwMfg"]
    if hw["designRef"]["digest"] != design_subj["digest"]:
        fail(f"{label}: designRef names a different board design")
    verify.require_link(a1, label, [rd(design_subj["name"], design_subj["digest"]["sha256"])], "board design")
    a1_rd = env_rd(bundle, f"att/{A1}")
    asm_ref = hb["predicate"]["manufacturing"]["boardAssembly"]["attestationRef"]
    if asm_ref["uri"] != f"file:att/{A1}" or asm_ref["digest"] != a1_rd["digest"]:
        fail("board hbom: boardAssembly reference does not match the A1 record")
    if lot_subj != a1["subject"][0]:
        fail("board hbom: lot subject does not match the A1 board lot")

    # parts[]: every lot traces to a signed shipment whose data matches, through an allowed channel.
    by_ref_des, shipments, inputs = {}, {}, [a1_rd]
    for part in hb["predicate"]["parts"]:
        mpn, lot, mfr = part["mpn"], part.get("lot"), part["manufacturer"]["name"]
        dist = part.get("distributor", {}).get("name")
        if "distributionRef" not in part or dist not in pol["shippers"]:
            fail(f"parts: {mpn} has no distribution record from a shipper in the policy")
        rel = part["distributionRef"]["uri"].removeprefix("file:")
        if rel not in shipments:
            label = f"distribution {Path(rel).name}"
            ship = trust.open(bundle / rel, pol["shippers"][dist]["role"], MFG_STEP)
            if ship["predicate"]["buildDefinition"]["buildType"] != mfg_step_type("distribution"):
                fail(f"{label}: wrong buildType")
            verify.as_slsa_provenance(ship, label)
            verify.require_gates(ship, label, "hwMfg")
            verify.require_files(bundle, ship, label)
            shipments[rel] = read_json(art / ship["subject"][0]["name"])
            inputs.append(env_rd(bundle, rel))
        if part["distributionRef"]["digest"] != env_rd(bundle, rel)["digest"]:
            fail(f"parts: {mpn} distribution reference does not match its digest")
        verify.require_link(a1, "board-assembly", [env_rd(bundle, rel)], "shipment record")
        ship = shipments[rel]
        if ship["shipper"]["name"] != dist:
            fail(f"parts: {mpn} names distributor {dist} but shipment {ship['id']} came from {ship['shipper']['name']}")
        line = next((ln for ln in ship["lines"] if ln["mpn"] == mpn and ln["manufacturer"] == mfr), None)
        if not line or line["lot"] != lot or line["dateCode"] != part.get("dateCode"):
            fail(f"parts: {mpn} lot {lot} does not match the distributor's shipment {ship['id']}")
        channel = mfr in pol["shippers"][dist]["authorizedFor"]
        if part.get("authorized") and not channel:
            fail(f"parts: {dist} is not an authorized channel for {mfr}, but {mpn} claims it is")
        if pol.get("requireAuthorizedChannel") and not part.get("authorized"):
            fail(f"parts: policy requires an authorized channel, and {mpn} lot {lot} was not bought through one")
        if "hbomRef" in part:
            part_check(bundle, a1, part, line)
        for r in part.get("refDes", []):
            by_ref_des[r] = (part, line)

    # The HBOM covers exactly the board design, and every placement is a listed lot.
    design_ref_des = {r: item["mpn"] for item in board_design["bom"] for r in item["refDes"]}
    for r, mpn in design_ref_des.items():
        if r not in by_ref_des or by_ref_des[r][0]["mpn"] != mpn:
            fail(f"parts: board design {r} ({mpn}) has no matching part in the HBOM")
    extra = sorted(set(by_ref_des) - set(design_ref_des))
    if extra:
        fail(f"parts: HBOM lists {', '.join(extra)}, which the board design does not have")

    builds = read_json(art / BUILD)
    used, units = {}, set()
    for serial, build in sorted(builds.items()):
        if set(build["placements"]) != set(design_ref_des):
            fail(f"board-assembly: board {serial} placements do not match the board design")
        for r, p in sorted(build["placements"].items()):
            part, line = by_ref_des[r]
            if (p["mpn"], p["lot"]) != (part["mpn"], part["lot"]):
                fail(f"board-assembly: board {serial} {r} is {p['mpn']} lot {p['lot']}, which the HBOM does not list")
            used[(p["mpn"], p["lot"])] = used.get((p["mpn"], p["lot"]), 0) + 1
            if "units" in line:
                if p.get("unit") not in line["units"]:
                    fail(f"board-assembly: board {serial} {r} unit {p.get('unit')} was never shipped to the EMS")
                if p["unit"] in units:
                    fail(f"board-assembly: unit {p['unit']} is placed on more than one board")
                units.add(p["unit"])
    for part, line in {id(v[1]): v for v in by_ref_des.values()}.values():
        if used.get((part["mpn"], part["lot"]), 0) > line["quantity"]:
            fail(f"board-assembly: more {part['mpn']} lot {part['lot']} placed than were shipped")

    # Board lot and yield.
    boards = read_units(art / BOARD_LOT)
    if lot_digest(boards) != lot_subj["digest"]["sha256"]:
        fail("board-assembly: board lot list does not match the attested lot digest")
    good = sorted(s for s, b in builds.items() if b["result"] == "pass")
    if sorted(boards) != good:
        fail("board-assembly: board lot is not the set of boards that passed test")
    if sorted(set(builds) - set(good)) != sorted(hw["yield"]["failed"]) or hw["yield"]["passed"] != len(good):
        fail("board-assembly: yield record does not account for every board built")
    mfr = hb["predicate"]["product"]["manufacturer"]["name"]
    subjects = {s["name"]: s["digest"] for s in a1["subject"]}
    for serial in boards:
        b = board_rd(mfr, serial)
        if subjects.get(b["name"]) != b["digest"]:
            fail(f"board-assembly: board {serial} is not a subject of the A1 record")

    for serial in received or []:
        if serial not in boards:
            fail(f"received board {serial} is not in the board lot")
    return {"lot": lot_subj, "inputs": [env_rd(bundle, f"att/{BOARD_HBOM}"), *inputs]}


def part_check(bundle, a1, part, line):
    """A part with its own HBOM: run its chain checks, and bind the lot, the HBOM and the shipped units to A1."""
    rel = part["hbomRef"]["uri"].removeprefix("file:")
    chip = (bundle / rel).parent.parent
    if part["hbomRef"]["digest"] != env_rd(bundle, rel)["digest"]:
        fail(f"parts: {part['mpn']} hbomRef does not match its digest")
    try:
        result = chip_check(chip, line.get("units"))
    except VerificationError as e:
        fail(f"parts: {part['mpn']} lot receipt check failed: {e}")
    chip_hbom = verify.decode(bundle / rel)
    if chip_hbom["predicate"]["product"].get("partNumber") != part["mpn"]:
        fail(f"parts: {part['mpn']} hbomRef is the HBOM of {chip_hbom['predicate']['product'].get('partNumber')}")
    if result["lot"]["name"] != f"urn:hslsa:lot:{part['lot']}":
        fail(f"parts: board claims {part['mpn']} lot {part['lot']}, but its HBOM names {result['lot']['name']}")
    verify.require_link(a1, "board-assembly", [result["lot"], env_rd(bundle, rel)], f"{part['mpn']} lot and HBOM")


def run(bundle, trust, policy_path, boards_path=None, vsa_key=None, vsa_dir=None):
    received = read_units(boards_path) if boards_path else None
    result = check(bundle, trust, policy_path, received)
    lot = result["lot"]
    print(
        f"board receipt check: PASSED for {lot['name']} sha256:{lot['digest']['sha256']}"
        + (f", {len(received)} received boards found in the lot" if received else "")
    )
    if vsa_key:
        claims = read_json(policy_path)["claims"]["board"]
        out = Path(vsa_dir) / "board.vsa.intoto.json"
        verify.vsa(lot, lot["name"], claims, result["inputs"], policy_path, vsa_key, out)
        print(f"VSA written to {out}: board {claims}")
    return result
