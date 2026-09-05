"""Command line: python -m hslsa <command> (run with PYTHONPATH=tools)."""

import argparse
import sys
from pathlib import Path

from . import design, hbom, mfg, verify
from .common import TrustRoot, VerificationError, keygen, load_signer
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
        elif a.cmd == "lot-digest":
            print(lot_digest(read_units(a.file)))
    except VerificationError as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
