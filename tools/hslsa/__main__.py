"""Command line: python -m hslsa <command> (run with PYTHONPATH=tools)."""

import argparse
import sys
from pathlib import Path

from . import board, caliptra, design, hbom, mfg, openlane, verify
from .common import TrustRoot, VerificationError, keygen, load_signer, write_json
from .lot import lot_digest, read_units


def main(argv=None):
    p = argparse.ArgumentParser(prog="hslsa", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate ECDSA P-256 keys, one per role")
    k.add_argument("--out", required=True)
    k.add_argument("roles", nargs="+")

    pk = sub.add_parser("pubkey", help="write the public key for an existing private key")
    pk.add_argument("--key", required=True)
    pk.add_argument("--out", required=True)

    kid = sub.add_parser("keyid", help="print the DSSE keyid for a public or private key")
    kid.add_argument("--key", required=True)

    t = sub.add_parser("trust-root", help="build a trust root from <role>.pub.pem files")
    t.add_argument("--keys", required=True)
    t.add_argument("--out", required=True)

    d = sub.add_parser("design", help="run and attest one design flow step")
    d.add_argument("step", choices=["source-freeze", "simulation", "synthesis", "release"])
    d.add_argument("--bundle", required=True)
    d.add_argument("--lock", required=True)
    d.add_argument("--key", required=True)
    d.add_argument("--cache", default=".hslsa-cache")
    d.add_argument("--trust-root")
    d.add_argument("--policy")

    m = sub.add_parser("mfg", help="emit signed F1 to F4 records for the scenario lot")
    m.add_argument("--bundle", required=True)
    m.add_argument("--scenario", required=True)
    m.add_argument("--keys", required=True)

    h = sub.add_parser("hbom", help="build, validate and sign the HBOM")
    h.add_argument("--bundle", required=True)
    h.add_argument("--lock", required=True)
    h.add_argument("--scenario", required=True)
    h.add_argument("--key", required=True)

    v = sub.add_parser("verify", help="tapeout and lot receipt checks, then VSAs")
    v.add_argument("--bundle", required=True)
    v.add_argument("--trust-root", required=True)
    v.add_argument("--policy", required=True)
    v.add_argument("--units", help="file with the serials of the units received")
    v.add_argument("--vsa-key")
    v.add_argument("--vsa-out")

    ol = sub.add_parser("openlane", help="OpenLane 2 flow with a signed record per step")
    ol.add_argument("action", choices=["run", "release", "verify", "compare"])
    ol.add_argument("--bundle", required=True)
    ol.add_argument("--run-dir", help="the OpenLane run directory the step records name files in")
    ol.add_argument("--lock")
    ol.add_argument("--key")
    ol.add_argument("--work", help="run: empty directory to unpack the design and run OpenLane in")
    ol.add_argument("--pdk-root", help="run: PDK root holding the enabled variant")
    ol.add_argument("--trust-root")
    ol.add_argument("--other-bundle", help="compare: the second run's bundle")
    ol.add_argument("--other-run-dir", help="compare: the second run's run directory")
    ol.add_argument("--report", help="compare: directory for the JSON and Markdown report")

    c = sub.add_parser("caliptra", help="the Caliptra example (e2e/caliptra)")
    csub = c.add_subparsers(dest="action", required=True)
    ca = csub.add_parser("ca", help="create the IDevID endorsement CA key")
    ca.add_argument("--keys", required=True)
    ca.add_argument("--name", default="HSLSA Example Caliptra IDevID CA")
    cf = csub.add_parser("firmware", help="sign provenance and SBOMs for the built images")
    cf.add_argument("--bundle", required=True)
    cf.add_argument("--lock", required=True)
    cf.add_argument("--build-dir", required=True)
    cf.add_argument("--key", required=True)
    cd = csub.add_parser("design", help="run and attest one design step")
    cd.add_argument("step", choices=["source-freeze", "lint", "rom-merge", "release"])
    cd.add_argument("--bundle", required=True)
    cd.add_argument("--lock", required=True)
    cd.add_argument("--key", required=True)
    cd.add_argument("--trust-root")
    cd.add_argument("--policy")
    cfab = csub.add_parser("fab", help="write the mask ROM every unit carries")
    cfab.add_argument("--bundle", required=True)
    cfab.add_argument("--devices", required=True)
    cp = csub.add_parser("provision", help="program every shipped unit and sign fw-provisioning records")
    cp.add_argument("--bundle", required=True)
    cp.add_argument("--devices", required=True)
    cp.add_argument("--keys", required=True)
    cp.add_argument("--device-bin", required=True)
    cp.add_argument("--scenario", required=True)
    cp.add_argument("--lock", required=True)
    ch = csub.add_parser("hbom", help="build, validate and sign the HBOM")
    ch.add_argument("--bundle", required=True)
    ch.add_argument("--lock", required=True)
    ch.add_argument("--scenario", required=True)
    ch.add_argument("--key", required=True)
    cv = csub.add_parser("verify", help="tapeout, lot, firmware and at-boot checks, then VSAs")
    cv.add_argument("--bundle", required=True)
    cv.add_argument("--trust-root", required=True)
    cv.add_argument("--policy", required=True)
    cv.add_argument("--units", required=True)
    cv.add_argument("--boots", required=True)
    cv.add_argument("--vsa-key")
    cv.add_argument("--vsa-out")
    b = sub.add_parser("board", help="board-level example: shipments, A1 and board HBOM, or the buyer's board check")
    b.add_argument("action", choices=["produce", "verify"])
    b.add_argument("--bundle", required=True)
    b.add_argument("--policy", required=True)
    b.add_argument("--chip-bundle", help="produce: the chip vendor's bundle that ships with the chips")
    b.add_argument("--scenario", help="produce: shipments and board build")
    b.add_argument("--design", help="produce: the released board design")
    b.add_argument("--keys", help="produce: directory of <role>.key.pem")
    b.add_argument("--trust-root", help="verify: trust root for the board's signers")
    b.add_argument("--boards", help="verify: file with the serials of the boards received")
    b.add_argument("--vsa-key")
    b.add_argument("--vsa-out")

    ld = sub.add_parser("lot-digest", help="compute the lot digest of a unit list")
    ld.add_argument("file")

    a = p.parse_args(argv)
    try:
        if a.cmd == "keygen":
            for role in a.roles:
                keygen(a.out, role)
        elif a.cmd == "pubkey":
            Path(a.out).write_text(load_signer(a.key).public_key.keyval["public"])
        elif a.cmd == "keyid":
            text = Path(a.key).read_text()
            if "PRIVATE" in text:
                print(load_signer(a.key).public_key.keyid)
            else:
                from .common import public_key_from_pem

                print(public_key_from_pem(text).keyid)
        elif a.cmd == "trust-root":
            TrustRoot.build(a.keys, a.out)
        elif a.cmd == "design":
            if a.step == "source-freeze":
                design.source_freeze(a.bundle, a.lock, a.key, a.cache)
            elif a.step == "simulation":
                design.simulation(a.bundle, a.lock, a.key)
            elif a.step == "synthesis":
                design.synthesis(a.bundle, a.lock, a.key)
            else:
                design.release(a.bundle, a.lock, a.key, a.trust_root, a.policy)
        elif a.cmd == "mfg":
            mfg.run(a.bundle, a.scenario, a.keys)
        elif a.cmd == "hbom":
            hbom.build(a.bundle, a.lock, a.scenario, a.key)
        elif a.cmd == "verify":
            verify.run(a.bundle, TrustRoot.load(a.trust_root), a.policy, a.units, a.vsa_key, a.vsa_out)
        elif a.cmd == "caliptra":
            run_caliptra(a)
        elif a.cmd == "board" and a.action == "produce":
            board.produce(a.bundle, a.chip_bundle, a.scenario, a.design, a.policy, a.keys)
        elif a.cmd == "board":
            board.run(a.bundle, TrustRoot.load(a.trust_root), a.policy, a.boards, a.vsa_key, a.vsa_out)
        elif a.cmd == "openlane":
            run_openlane(a)
        elif a.cmd == "lot-digest":
            print(lot_digest(read_units(a.file)))
    except VerificationError as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1
    return 0


def run_openlane(a):
    if a.action == "run":
        openlane.run(a.bundle, a.lock, a.key, a.work, a.pdk_root)
    elif a.action == "release":
        openlane.release(a.bundle, a.run_dir, a.key, a.trust_root, a.lock)
    elif a.action == "verify":
        records, final = openlane.verify(a.bundle, a.run_dir, TrustRoot.load(a.trust_root))
        print(
            f"openlane tapeout check: PASSED, {len(records)} step records, "
            f"{final['name']} sha256:{final['digest']['sha256']}"
        )
    else:
        other_trust = Path(a.other_bundle) / "trust-root.json"
        report = openlane.compare(
            a.bundle,
            a.run_dir,
            a.other_bundle,
            a.other_run_dir,
            TrustRoot.load(a.trust_root),
            TrustRoot.load(other_trust),
        )
        out = Path(a.report)
        write_json(out / "reproducibility.json", report)
        (out / "reproducibility.md").write_text(openlane.markdown(report))
        if a.key:
            openlane.rebuild_record(report, a.bundle, a.key, out / "rebuild.intoto.json")
        print(openlane.markdown(report))


def run_caliptra(a):
    if a.action == "ca":
        caliptra.identity_ca(a.keys, a.name)
    elif a.action == "firmware":
        caliptra.firmware(a.bundle, a.lock, a.build_dir, a.key)
    elif a.action == "design":
        if a.step == "source-freeze":
            caliptra.source_freeze(a.bundle, a.lock, a.key)
        elif a.step == "lint":
            caliptra.lint(a.bundle, a.lock, a.key)
        elif a.step == "rom-merge":
            caliptra.rom_merge(a.bundle, a.lock, a.key)
        else:
            caliptra.release(a.bundle, a.key, a.trust_root, a.policy)
    elif a.action == "fab":
        caliptra.fab(a.bundle, a.devices)
    elif a.action == "provision":
        caliptra.provision(a.bundle, a.devices, a.keys, a.device_bin, a.scenario, a.lock)
    elif a.action == "hbom":
        caliptra.hbom(a.bundle, a.lock, a.scenario, a.key)
    else:
        caliptra.verify(a.bundle, TrustRoot.load(a.trust_root), a.policy, a.units, a.boots, a.vsa_key, a.vsa_out)


if __name__ == "__main__":
    sys.exit(main())
