"""Wafer and Package/Test tracks: signed F1 to F4 records for a simulated lot.

No fab runs in CI, so the physical data (wafer maps, genealogy, test results)
comes from a scenario file. Everything downstream of that data is real: each
site signs with its own key, names its subjects the way the spec does, links
to the previous step by digest, and copies the design release into designRef.
"""

import base64
import json
from pathlib import Path

from .common import (
    MFG_STEP,
    file_rd,
    load_signer,
    mfg_step_type,
    now,
    rd,
    read_json,
    sign,
    statement,
    write_json,
)
from .lot import lot_digest, write_units

ATT = {
    "wafer-fab": "mfg-f1-wafer-fab.intoto.json",
    "wafer-sort": "mfg-f2-wafer-sort.intoto.json",
    "packaging": "mfg-f3-packaging.intoto.json",
    "final-test": "mfg-f4-final-test.intoto.json",
}
SIGNER = {"wafer-fab": "fab-site", "wafer-sort": "sort-site", "packaging": "osat-site", "final-test": "test-site"}


def record(bundle, step, subjects, external, deps, hw, keys):
    pred = {
        "buildDefinition": {
            "buildType": mfg_step_type(step),
            "externalParameters": external,
            "resolvedDependencies": deps,
        },
        "runDetails": {
            "builder": {"id": f"urn:hslsa:site:{hw['site']['name'].lower().replace(' ', '-')}"},
            "metadata": {"invocationId": f"{step}:{external.get('lotId', '')}", "finishedOn": now()},
        },
        "hwMfg": {"step": step, "confidential": [], **hw},
    }
    path = Path(bundle) / "att" / ATT[step]
    env = sign(statement(subjects, MFG_STEP, pred), load_signer(Path(keys) / f"{SIGNER[step]}.key.pem"), path)
    print(f"{step}: signed by {SIGNER[step]}")
    return rd(f"att/{ATT[step]}", env["digest"]["sha256"])


def passed(checks):
    return [{"name": c, "result": "pass"} for c in checks]


def run(bundle, scenario_path, keys):
    bundle = Path(bundle)
    art = bundle / "artifacts"
    sc = read_json(scenario_path)
    release = read_json(bundle / "att" / "design-release.intoto.json")
    release_rd = file_rd(bundle / "att" / "design-release.intoto.json", "att/design-release.intoto.json")
    final = json.loads(base64.b64decode(release["payload"]))["subject"][0]
    design_ref = {"name": final["name"], "digest": final["digest"], "release": release_rd}

    # F1: wafer fabrication
    fab, lot = sc["fab"], sc["waferLot"]
    wafer_lot = rd(f"urn:hslsa:wafer-lot:{fab['id']}:{lot['lotId']}", lot_digest(lot["wafers"]))
    f1 = record(
        bundle,
        "wafer-fab",
        [wafer_lot],
        {"lotId": lot["lotId"], "maskSetId": fab["maskSetId"], "processNode": fab["processNode"]},
        [release_rd],
        {"site": fab["site"], "designRef": design_ref, "checks": passed(["mask-vs-gds-xor", "inline-parametrics"])},
        keys,
    )

    # F2: wafer sort, one map entry per die
    sort = sc["sort"]
    failed_dies = {tuple(d) for d in sort["failedDies"]}
    dies = [
        {"wafer": w, "x": x, "y": y, "bin": "fail" if (w, x, y) in failed_dies else "pass"}
        for w in lot["wafers"]
        for y in range(sort["grid"][1])
        for x in range(sort["grid"][0])
    ]
    write_json(art / "wafer-maps.json", {"waferLot": wafer_lot["name"], "dies": dies})
    good = [d for d in dies if d["bin"] == "pass"]
    f2 = record(
        bundle,
        "wafer-sort",
        [file_rd(art / "wafer-maps.json")],
        {"lotId": lot["lotId"], "probeProgram": sort["program"]},
        [f1, wafer_lot],
        {
            "site": sort["site"],
            "designRef": design_ref,
            "yield": {"in": len(dies), "passed": len(good), "failed": len(dies) - len(good)},
            "checks": passed(["probe"]),
        },
        keys,
    )

    # F3: packaging, with die-to-unit genealogy
    pkg = sc["packaging"]
    genealogy = {
        f"{pkg['serialPrefix']}{i + 1:05d}": {"waferLot": wafer_lot["name"], **{k: d[k] for k in ("wafer", "x", "y")}}
        for i, d in enumerate(good[: pkg["units"]])
    }
    write_json(art / "genealogy.json", genealogy)
    write_units(art / "packaged-lot.txt", genealogy)
    packaged = rd(f"urn:hslsa:assembly-lot:{pkg['assemblyLot']}", lot_digest(genealogy))
    f3 = record(
        bundle,
        "packaging",
        [packaged, file_rd(art / "genealogy.json")],
        {"lotId": pkg["assemblyLot"], "packageType": pkg["packageType"]},
        [f2, file_rd(art / "wafer-maps.json")],
        {
            "site": pkg["site"],
            "designRef": design_ref,
            "checks": passed(["die-attach", "wire-bond", "x-ray-sample", "marking"]),
        },
        keys,
    )

    # F4: final test, names the shipped lot
    ft = sc["finalTest"]
    shipped = sorted(set(genealogy) - set(ft["failedUnits"]))
    write_units(art / "shipped-lot.txt", shipped)
    write_json(
        art / "final-test-results.json", {u: ("fail" if u in ft["failedUnits"] else "pass") for u in sorted(genealogy)}
    )
    shipped_lot = rd(f"urn:hslsa:lot:{ft['lotId']}", lot_digest(shipped))
    record(
        bundle,
        "final-test",
        [shipped_lot, file_rd(art / "final-test-results.json")],
        {"lotId": ft["lotId"], "testProgram": ft["program"]},
        [f3, packaged],
        {
            "site": ft["site"],
            "designRef": design_ref,
            "yield": {"in": len(genealogy), "passed": len(shipped), "failed": sorted(ft["failedUnits"])},
            "checks": passed(["final-test-per-unit", "yield-within-limits"]),
        },
        keys,
    )
    print(f"shipped lot {shipped_lot['name']}: {len(shipped)} units, digest {shipped_lot['digest']['sha256']}")
