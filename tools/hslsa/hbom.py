"""HBOM: build the product owner's bill of materials for the test part, validate it, sign it."""

import base64
import json
from pathlib import Path

import jsonschema

from .common import HBOM, VerificationError, file_rd, load_signer, rd, read_json, sign, statement
from .design import STEPS, att_name
from .lot import lot_digest, read_units
from .mfg import ATT

REPO = Path(__file__).resolve().parents[2]
SCHEMA = REPO / "hbom" / "hbom-predicate-v0.1.schema.json"
FLOW_ENUM = {"source-freeze": "other", "simulation": "simulation", "synthesis": "synthesis", "release": "release"}


def validate(predicate):
    try:
        jsonschema.Draft202012Validator(read_json(SCHEMA)).validate(predicate)
    except jsonschema.ValidationError as e:
        raise VerificationError(
            f"HBOM does not match its schema at /{'/'.join(map(str, e.absolute_path))}: {e.message}"
        ) from e


def att_ref(bundle, name):
    ref = file_rd(Path(bundle) / "att" / name)
    return {"uri": f"file:att/{name}", "digest": ref["digest"]}


def payload(bundle, name):
    return json.loads(base64.b64decode(read_json(Path(bundle) / "att" / name)["payload"]))


def build(bundle, lock_path, scenario_path, key):
    bundle = Path(bundle)
    lock, sc = read_json(lock_path), read_json(scenario_path)
    src = lock["source"]
    flow = []
    for step in STEPS + ["release"]:
        hw = payload(bundle, att_name(step))["predicate"]["hwFlow"]
        tools = [{k: t[k] for k in ("name", "version", "digest")} for t in hw["tools"]]
        flow.append(
            {
                "step": FLOW_ENUM[step],
                "tools": tools or [{"name": "hslsa", "version": "0.1"}],
                "provenanceRef": att_ref(bundle, att_name(step)),
            }
        )
    final = payload(bundle, att_name("release"))["subject"][0]
    shipped = read_units(bundle / "artifacts" / "shipped-lot.txt")
    fab, pkg, ft, sort = sc["fab"], sc["packaging"], sc["finalTest"], sc["sort"]
    predicate = {
        "hbomVersion": "0.1",
        "product": sc["product"],
        "design": {
            "ipBlocks": [
                {
                    "name": lock["design"],
                    "kind": "soft",
                    "supplier": {"name": "YosysHQ"},
                    "license": "ISC",
                    "source": {"uri": src["repo"], "digest": {"gitCommit": src["commit"]}},
                }
            ],
            "rtlSources": [
                {"repo": src["repo"], "path": name, "digest": {"sha256": digest}, "language": "Verilog"}
                for name, digest in sorted(src["files"].items())
            ],
            "flow": flow,
            "finalLayout": {"uri": f"file:artifacts/{final['name']}", "digest": final["digest"]},
        },
        "manufacturing": {
            "fab": {
                "foundry": fab["site"],
                "processNode": fab["processNode"],
                "maskSetId": fab["maskSetId"],
                "attestationRef": att_ref(bundle, ATT["wafer-fab"]),
            },
            "waferLots": [{"lotId": sc["waferLot"]["lotId"], "waferIds": sc["waferLot"]["wafers"]}],
            "assembly": {
                "osat": pkg["site"],
                "packageType": pkg["packageType"],
                "assemblyLot": pkg["assemblyLot"],
                "attestationRef": att_ref(bundle, ATT["packaging"]),
            },
            "test": [
                {
                    "stage": "wafer-sort",
                    "site": sort["site"],
                    "program": sort["program"],
                    "resultsRef": att_ref(bundle, ATT["wafer-sort"]),
                },
                {
                    "stage": "final-test",
                    "site": ft["site"],
                    "program": ft["program"],
                    "resultsRef": att_ref(bundle, ATT["final-test"]),
                },
            ],
        },
    }
    validate(predicate)
    subjects = [rd(final["name"], final["digest"]["sha256"]), rd(f"urn:hslsa:lot:{ft['lotId']}", lot_digest(shipped))]
    sign(statement(subjects, HBOM, predicate), load_signer(key), bundle / "att" / "hbom.intoto.json")
    print(f"hbom: signed, {len(flow)} flow steps, lot of {len(shipped)} units")
