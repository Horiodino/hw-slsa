"""Caliptra example: one chain from RTL to a booted device with a hardware identity.

Producer side, in the order e2e/caliptra/run.sh calls it:

  firmware     SLSA Provenance v1 and a CycloneDX SBOM for the ROM and the
               signed FMC + runtime bundle built by caliptra-builder
  design       step 0 source freeze of the pinned Caliptra RTL, step 1 Verilator
               lint, step 6a ROM merge (with rom-readback), and the release
  fab          the "silicon": the ROM taken out of the released design
  provision    per unit: inject UDS and field entropy, burn fuses, export the
               IDevID CSR from the real ROM, endorse it, write the firmware to
               flash, then sign one fw-provisioning record per unit
  hbom         the product owner's HBOM, with firmware[] filled in

Buyer side, `verify`: the tapeout and lot receipt checks from verify.py, then
the Firmware track and the spec's at-boot check on every received unit that
was booted, then SLSA VSAs.
"""

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import dice
from . import hbom as hbom_mod
from .common import (
    HBOM,
    NS,
    TrustRoot,
    VerificationError,
    builder,
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
from .design import att_name, check, deterministic_tar, finish, predicate, tool, unpack
from .lot import lot_digest, read_units
from .mfg import ATT
from .verify import as_slsa_provenance, env_rd, fail, lot_check, require_files, tapeout_check, vsa

SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"
FW_PROVISIONING = f"{NS}/fw-provisioning/v0.1"
FW_BUILD_TYPE = f"{NS}/firmware/caliptra-builder@v1"
PROVISION_TYPE = f"{NS}/fw-provisioning/step/provision@v1"
FW_ATT = {"rom": "fw-rom.intoto.json", "bundle": "fw-bundle.intoto.json"}
IMAGES = {
    "rom": "caliptra-rom.bin",
    "bundle": "caliptra-fw-bundle.bin",
    "fmc": "caliptra-fmc.bin",
    "runtime": "caliptra-runtime.bin",
}
RTL_TAR, DESIGN_TAR, ROM_HEX = "caliptra-rtl.tar", "caliptra-design.tar", "caliptra-rom.hex"
LIFECYCLE = {"manufacturing": 1, "production": 3}


def sha384_bytes(data):
    return hashlib.sha384(data).hexdigest()


def rd2(path, name=None):
    """A file descriptor with both sha256 (the chain's link digest) and sha384 (what Caliptra measures)."""
    data = Path(path).read_bytes()
    return {"name": name or Path(path).name, "digest": {"sha256": sha256_bytes(data), "sha384": sha384_bytes(data)}}


def payload(path):
    return json.loads(base64.b64decode(read_json(path)["payload"]))


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


# Firmware track: image builds


def parse_tree(text, checkout):
    """Packages from `cargo tree --prefix none --format {p}`, deduplicated."""
    pkgs = {}
    for line in text.splitlines():
        line = line.replace(" (*)", "").strip()
        m = re.match(r"^(\S+) v(\S+)(?P<macro> \(proc-macro\))?(?: \((?P<src>.+)\))?$", line)
        if not m:
            continue
        src = m.group("src") or "registry"
        if src.startswith(str(checkout)):
            src = "path:" + os.path.relpath(src, checkout)
        pkgs[(m.group(1), m.group(2))] = {"source": src, "buildOnly": bool(m.group("macro"))}
    return pkgs


def cargo_lock_checksums(lock_text):
    lock = tomllib.loads(lock_text)
    return {(p["name"], p["version"]): p["checksum"] for p in lock.get("package", []) if "checksum" in p}


def cyclonedx(image, image_rd, tree_text, lock_text, sw, checkout):
    """CycloneDX 1.6 SBOM for one firmware image, from the crates cargo compiled into it."""
    sums = cargo_lock_checksums(lock_text)
    components = []
    for (name, version), info in sorted(parse_tree(tree_text, checkout).items()):
        comp = {
            "type": "library",
            "bom-ref": f"pkg:cargo/{name}@{version}",
            "name": name,
            "version": version,
            "purl": f"pkg:cargo/{name}@{version}",
            "scope": "excluded" if info["buildOnly"] else "required",
        }
        if info["source"].startswith("path:"):
            comp["externalReferences"] = [
                {"type": "vcs", "url": f"git+{sw['repo']}@{sw['commit']}#{info['source'][5:]}"}
            ]
        elif info["source"].startswith("http"):
            comp["externalReferences"] = [{"type": "vcs", "url": f"git+{info['source']}"}]
        elif (name, version) in sums:
            comp["hashes"] = [{"alg": "SHA-256", "content": sums[(name, version)]}]
        components.append(comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "firmware",
                "bom-ref": image,
                "name": image,
                "hashes": [
                    {"alg": "SHA-256", "content": image_rd["digest"]["sha256"]},
                    {"alg": "SHA-384", "content": image_rd["digest"]["sha384"]},
                ],
            },
            "tools": {"components": [{"type": "application", "name": "hslsa", "version": "0.1"}]},
        },
        "components": components,
    }


def fw_statement(subjects, target, external, deps, byproducts, started):
    run = builder()
    run["metadata"].update({"startedOn": started, "finishedOn": now()})
    run["byproducts"] = byproducts
    pred = {
        "buildDefinition": {
            "buildType": FW_BUILD_TYPE,
            "externalParameters": {"target": target, **external},
            "internalParameters": {"CALIPTRA_IMAGE_NO_GIT_REVISION": "1"},
            "resolvedDependencies": deps,
        },
        "runDetails": run,
    }
    return statement(subjects, SLSA_PROVENANCE, pred)


def firmware(bundle, lock_path, build_dir, key):
    """Sign SLSA provenance for the images built by caliptra-builder in build_dir."""
    started = now()
    lock, build = read_json(lock_path), Path(build_dir)
    sw = lock["caliptraSw"]
    checkout = Path(lock_path).parent / ".src" / "caliptra-sw"
    art = Path(bundle) / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    for name in IMAGES.values():
        shutil.copy(build / name, art / name)
    shutil.copy(build / "fw-manifest.json", art / "fw-manifest.json")
    lock_text = (checkout / "Cargo.lock").read_text()
    head = git(checkout, "rev-parse", "HEAD")
    if head != sw["commit"]:
        raise SystemExit(f"caliptra-sw checkout is at {head}, lock pins {sw['commit']}")
    deps = [
        {"name": "caliptra-sw", "digest": {"gitCommit": sw["commit"]}, "uri": f"git+{sw['repo']}@{sw['tag']}"},
        rd("Cargo.lock", sha256_bytes(lock_text.encode())),
        {"name": "rust-toolchain", "uri": f"rustup:{(build / 'rustc-version.txt').read_text().strip()}"},
    ]
    signer = load_signer(key)

    sboms = {}
    for image in ("rom", "fmc", "runtime"):
        sbom = cyclonedx(
            IMAGES[image], rd2(art / IMAGES[image]), (build / f"tree-{image}.txt").read_text(), lock_text, sw, checkout
        )
        write_json(art / f"sbom-{image}.cdx.json", sbom)
        sboms[image] = file_rd(art / f"sbom-{image}.cdx.json")

    rom = fw_statement(
        [rd2(art / IMAGES["rom"])],
        "rom-no-log",
        {"source": sw["repo"], "tag": sw["tag"], "command": "caliptra-builder --rom-no-log", "features": ["cfi"]},
        deps,
        [sboms["rom"], file_rd(build / "build-rom.log")],
        started,
    )
    sign(rom, signer, Path(bundle) / "att" / FW_ATT["rom"])
    manifest = read_json(art / "fw-manifest.json")
    fw = fw_statement(
        [rd2(art / IMAGES[i]) for i in ("bundle", "fmc", "runtime")],
        "fw",
        {
            "source": sw["repo"],
            "tag": sw["tag"],
            "command": f"caliptra-builder --fw --fw-svn {lock['firmware']['fwSvn']}",
            "fwSvn": lock["firmware"]["fwSvn"],
            "signingKeys": "caliptra-image-fake-keys (Caliptra's public test keys)",
        },
        deps,
        [sboms["fmc"], sboms["runtime"], file_rd(art / "fw-manifest.json"), file_rd(build / "build-fw.log")],
        started,
    )
    sign(fw, signer, Path(bundle) / "att" / FW_ATT["bundle"])
    print(f"firmware: ROM sha384:{rom['subject'][0]['digest']['sha384'][:16]}..., bundle svn {manifest['svn']}, signed")


# Design track


def rtl_files(root, file_list):
    """Every file the lint command reads: the file list, the files it names and everything in its include dirs."""
    env = {"CALIPTRA_ROOT": str(root), **rtl_env(root)}
    files = {file_list}
    for line in (root / file_list).read_text().splitlines():
        line = line.strip()
        for k, v in env.items():
            line = line.replace("${" + k + "}", v)
        if not line or line.startswith("//"):
            continue
        if line.startswith("+incdir+"):
            d = Path(line[len("+incdir+") :])
            files |= {str(p.relative_to(root)) for p in d.iterdir() if p.is_file()}
        else:
            files.add(str(Path(line).relative_to(root)))
    return sorted(files)


def rtl_env(root):
    return {
        "CALIPTRA_PRIM_ROOT": f"{root}/src/caliptra_prim_generic",
        "CALIPTRA_PRIM_MODULE_PREFIX": "caliptra_prim_generic",
    }


def source_freeze(bundle, lock_path, key):
    """Step 0: check the RTL checkouts are the pinned commits and trees, and freeze what lint reads."""
    started = now()
    lock = read_json(lock_path)
    src = Path(lock_path).parent / ".src"
    rtl, abr = lock["caliptraRtl"], lock["adamsBridge"]
    root = src / "caliptra-rtl"
    mismatched = []
    for repo, pin in ((root, rtl), (root / "submodules" / "adams-bridge", abr)):
        head, tree = git(repo, "rev-parse", "HEAD"), git(repo, "rev-parse", "HEAD^{tree}")
        if (head, tree) != (pin["commit"], pin["tree"]):
            mismatched.append(f"{repo.name} at {head} tree {tree}")
    files = rtl_files(root, lock["rtl"]["fileList"])
    art = Path(bundle) / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    deterministic_tar(root, files, art / RTL_TAR)
    deps = [
        {"name": "caliptra-rtl", "digest": {"gitCommit": rtl["commit"]}, "uri": f"git+{rtl['repo']}"},
        {"name": "adams-bridge", "digest": {"gitCommit": abr["commit"]}, "uri": f"git+{abr['repo']}"},
    ]
    if os.environ.get("GITHUB_SHA"):
        deps.append(
            {
                "name": "hw-slsa",
                "digest": {"gitCommit": os.environ["GITHUB_SHA"]},
                "uri": f"git+{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}",
            }
        )
    pred = predicate(
        "source-freeze",
        {"design": "caliptra", "top": lock["rtl"]["top"], "fileList": lock["rtl"]["fileList"], "files": len(files)},
        deps,
        [],
        [check("inputs-pinned", not mismatched, "; ".join(mismatched) or "commits and trees match caliptra.lock.json")],
        [],
        started,
    )
    finish(bundle, "source-freeze", [file_rd(art / RTL_TAR)], pred, load_signer(key))


def lint(bundle, lock_path, key):
    """Step 1: Verilator lint of the whole Caliptra top level from the frozen archive."""
    started = now()
    lock = read_json(lock_path)
    art = Path(bundle) / "artifacts"
    flags = lock["rtl"]["verilatorFlags"]
    with tempfile.TemporaryDirectory() as work:
        unpack(art / RTL_TAR, work)
        env = {**os.environ, "CALIPTRA_ROOT": work, "CALIPTRA_AXI4PC_DIR": work, **rtl_env(work)}
        cmd = ["verilator", "--lint-only", *flags, "-f", lock["rtl"]["fileList"], "--top-module", lock["rtl"]["top"]]
        proc = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True)
    log = (proc.stdout + proc.stderr).replace(work, "$CALIPTRA_ROOT")
    (art / "rtl-lint.log").write_text(log)
    errors, warnings = log.count("%Error"), log.count("%Warning")
    pred = predicate(
        "lint",
        {"top": lock["rtl"]["top"], "command": " ".join(cmd[:-4]) + " -f <fileList> --top-module <top>"},
        [file_rd(art / RTL_TAR)],
        [tool("verilator", ["--version"])],
        [check("verilator-lint", proc.returncode == 0 and errors == 0, f"exit {proc.returncode}, {errors} errors")],
        [],
        started,
    )
    pred["hwFlow"]["metrics"] = {"lintWarnings": warnings, "files": len(tarfile.open(art / RTL_TAR).getnames())}
    finish(bundle, "lint", [file_rd(art / "rtl-lint.log")], pred, load_signer(key))


def rom_hex(data):
    """The ROM in the format caliptra-rtl's testbench loads into its ROM macro ($readmemh, one byte per word)."""
    lines = ["@00000000"] + [" ".join(f"{b:02X}" for b in data[i : i + 16]) for i in range(0, len(data), 16)]
    return ("\n".join(lines) + "\n").encode()


def read_rom_hex(text):
    out = bytearray()
    for line in text.splitlines():
        if line and not line.startswith("@"):
            out += bytes(int(x, 16) for x in line.split())
    return bytes(out)


def frozen_digest(lock_path, name):
    """The ROM digest the Caliptra TAC froze, from FROZEN_IMAGES.sha384sum in the pinned caliptra-sw."""
    checkout = Path(lock_path).parent / ".src" / "caliptra-sw"
    for line in (checkout / "FROZEN_IMAGES.sha384sum").read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == name:
            return parts[0]
    raise SystemExit(f"{name} is not listed in FROZEN_IMAGES.sha384sum")


def rom_merge(bundle, lock_path, key):
    """Step 6a: merge the ROM image into the design, and prove the merged design holds exactly that image."""
    started = now()
    lock = read_json(lock_path)
    bundle = Path(bundle)
    art = bundle / "artifacts"
    rom = (art / IMAGES["rom"]).read_bytes()
    rom_att = bundle / "att" / FW_ATT["rom"]
    provenance = payload(rom_att)["subject"][0]["digest"]
    with tempfile.TemporaryDirectory() as work:
        unpack(art / RTL_TAR, work)
        defines = (Path(work) / lock["rom"]["definesFile"]).read_text()
        size = int(re.search(rf"`define\s+{lock['rom']['sizeDefine']}\s+(\d+)", defines).group(1))
        names = tarfile.open(art / RTL_TAR).getnames()
        (Path(work) / "rom").mkdir()
        (Path(work) / "rom" / "program.hex").write_bytes(rom_hex(rom))
        deterministic_tar(work, names + ["rom/program.hex"], art / DESIGN_TAR)
    (art / ROM_HEX).write_bytes(rom_hex(rom))
    # Readback: extract the ROM from the merged design itself, not from the file just written.
    with tarfile.open(art / DESIGN_TAR) as tar:
        readback = read_rom_hex(tar.extractfile("rom/program.hex").read().decode())
    frozen = frozen_digest(lock_path, lock["rom"]["frozenName"])
    pred = predicate(
        "rom-merge",
        {"romMacro": "imem", "romFormat": "$readmemh bytes", "sizeDefine": lock["rom"]["sizeDefine"]},
        [file_rd(art / RTL_TAR), rd2(art / IMAGES["rom"]), env_rd(bundle, FW_ATT["rom"])],
        [],
        [
            check("rom-fits-macro", len(rom) == size, f"{len(rom)} bytes, macro holds {size}"),
            check(
                "rom-readback",
                sha384_bytes(readback) == provenance["sha384"],
                f"bits read back from the merged design: sha384:{sha384_bytes(readback)}",
            ),
            check(
                "rom-matches-frozen",
                sha384_bytes(rom) == frozen,
                f"Caliptra TAC frozen {lock['rom']['frozenName']}: sha384:{frozen}",
            ),
        ],
        [],
        started,
    )
    finish(bundle, "rom-merge", [file_rd(art / DESIGN_TAR), file_rd(art / ROM_HEX)], pred, load_signer(key))


def release(bundle, key, trust_root, policy_path):
    """Tapeout release: run the tapeout check on the steps, then sign the merged design."""
    started = now()
    bundle = Path(bundle)
    policy = read_json(policy_path)
    steps = policy["design"]["requiredSteps"]
    try:
        tapeout_check(bundle, TrustRoot.load(trust_root), policy, release=False)
        gate = check("tapeout-policy", True, "all design steps present, signed and linked")
    except VerificationError as e:
        gate = check("tapeout-policy", False, str(e))
    pred = predicate(
        "release",
        {
            "design": "caliptra",
            "finalArtifact": DESIGN_TAR,
            "finalArtifactKind": "RTL with the ROM merged (stands in for GDS until physical design runs)",
        },
        [env_rd(bundle, att_name(s)) for s in steps],
        [],
        [gate],
        [],
        started,
    )
    finish(bundle, "release", [file_rd(bundle / "artifacts" / DESIGN_TAR)], pred, load_signer(key))


def fab(bundle, devices):
    """The silicon every unit carries: the ROM exactly as the released design holds it."""
    rel = payload(Path(bundle) / "att" / att_name("release"))["subject"][0]
    design = Path(bundle) / "artifacts" / rel["name"]
    if sha256_file(design) != rel["digest"]["sha256"]:
        raise SystemExit("released design does not match its release record")
    with tarfile.open(design) as tar:
        rom = read_rom_hex(tar.extractfile("rom/program.hex").read().decode())
    Path(devices).mkdir(parents=True, exist_ok=True)
    (Path(devices) / "rom.bin").write_bytes(rom)
    print(f"fab: mask ROM sha384:{sha384_bytes(rom)[:16]}... taken from the released design")


# Identity CA and provisioning


def identity_ca(keys_dir, name):
    """The product line's IDevID endorsement CA (an HSM in production; a local P-384 key here)."""
    keys = Path(keys_dir)
    key = ec.generate_private_key(ec.SECP384R1())
    (keys / "identity-ca.key.pem").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    (keys / "identity-ca.key.pem").chmod(0o600)
    (keys / "identity-ca.pub.pem").write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    (keys / "identity-ca.name.txt").write_text(name)


def endorse(csr, ca_key, ca_name):
    """Issue the IDevID certificate for a CSR the device exported, keeping the extensions it asked for."""
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_name)])
    b = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc))
    )
    for ext in csr.extensions:
        b = b.add_extension(ext.value, ext.critical)
    return b.sign(ca_key, hashes.SHA384())


def fuse_map(unit, manifest, lifecycle, fw_svn_fuse):
    """The fuse values a programming station burns, except secrets. Hex strings are what the device reads."""
    return {
        "vendor_pk_hash": manifest["vendorPkHash"],
        "owner_pk_hash": manifest["ownerPkHash"],
        "fuse_pqc_key_type": manifest["pqcKeyType"],
        "fw_svn": fw_svn_fuse,
        "anti_rollback_disable": False,
        "fuse_ecc_revocation": 0,
        "fuse_lms_revocation": 0,
        "fuse_mldsa_revocation": 0,
        "soc_manifest_svn": 0,
        "soc_manifest_max_svn": 128,
        "idevid_cert_attr.ueid": "01" + unit.encode().ljust(16, b"\0").hex(),
        "life_cycle": lifecycle,
        "debug_locked": True,
    }


def device_fuses(unit, fuses, secrets):
    """The JSON the device model reads: what is physically in this unit's fuse bank."""
    return {
        "serial": unit,
        "udsSeed": secrets["uds_seed"],
        "fieldEntropy": secrets["field_entropy"],
        "vendorPkHash": fuses["vendor_pk_hash"],
        "ownerPkHash": fuses["owner_pk_hash"],
        "fwSvnFuse": fuses["fw_svn"],
        "pqcKeyType": fuses["fuse_pqc_key_type"],
        "lifecycle": fuses["life_cycle"],
    }


def canonical_digest(obj):
    return sha256_bytes(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode())


def provision(bundle, devices, keys_dir, device_bin, scenario_path, lock_path):
    """Program every shipped unit at the final test station, then sign one record per unit."""
    bundle, devices, keys = Path(bundle), Path(devices), Path(keys_dir)
    sc, lock = read_json(scenario_path), read_json(lock_path)
    art = bundle / "artifacts"
    station = sc["provisioning"]
    trust = TrustRoot.load(bundle / "trust-root.json")
    ca_key = serialization.load_pem_private_key((keys / "identity-ca.key.pem").read_bytes(), password=None)
    ca_name = (keys / "identity-ca.name.txt").read_text()
    manifest = read_json(art / "fw-manifest.json")
    image = art / IMAGES["bundle"]

    # The station checks the image's provenance before it writes a single unit.
    fw = trust.open(bundle / "att" / FW_ATT["bundle"], "firmware-platform", SLSA_PROVENANCE)
    verified = file_rd(image)["digest"]["sha256"] in {s["digest"]["sha256"] for s in fw["subject"]}
    if not verified:
        raise SystemExit("provisioning: firmware bundle does not match its provenance; refusing to write")

    (art / "identity").mkdir(exist_ok=True)
    (art / "provisioning").mkdir(exist_ok=True)
    for unit in read_units(art / "shipped-lot.txt"):
        udir = devices / unit
        udir.mkdir(parents=True, exist_ok=True)
        secrets = {"uds_seed": os.urandom(64).hex(), "field_entropy": os.urandom(32).hex()}
        key_ids = {k: f"{station['hsm']}:{uuid.uuid4()}" for k in secrets}
        fuses = fuse_map(unit, manifest, "manufacturing", lock["firmware"]["fwSvnFuse"])
        write_json(udir / "fuses.json", device_fuses(unit, fuses, secrets))
        with tempfile.TemporaryDirectory() as work:
            subprocess.run(
                [device_bin, "csr", "--rom", devices / "rom.bin", "--fuses", udir / "fuses.json", "--out", work],
                check=True,
                capture_output=True,
            )
            csr_der = (Path(work) / "idevid-csr-ecc384.der").read_bytes()
        csr = x509.load_der_x509_csr(csr_der)
        dice.check_csr(csr, f"{unit} IDevID CSR")
        cert = endorse(csr, ca_key, ca_name)
        (art / "identity" / f"{unit}.csr.der").write_bytes(csr_der)
        (art / "identity" / f"{unit}.idevid.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))

        shutil.copy(image, udir / "flash.bin")
        fuses["life_cycle"] = "production"
        write_json(udir / "fuses.json", device_fuses(unit, fuses, secrets))
        burned = read_json(udir / "fuses.json")
        readback = {k: burned[k] for k in ("vendorPkHash", "ownerPkHash", "fwSvnFuse", "pqcKeyType", "lifecycle")}
        log = {
            "unit": unit,
            "lotId": sc["finalTest"]["lotId"],
            "stage": "final-test",
            "station": station,
            "fuses": fuses,
            "fuseReadback": {"sha256": canonical_digest(readback)},
            "secrets": [{"field": k, "keyId": key_ids[k], "origin": f"injected by {station['hsm']}"} for k in secrets],
            "images": [
                {
                    "name": IMAGES["bundle"],
                    "role": "firmware bundle (FMC and runtime)",
                    "storage": "external-flash",
                    "digest": rd2(image)["digest"],
                    "readback": {"sha256": sha256_file(udir / "flash.bin")},
                    "provenanceVerified": verified,
                }
            ],
            "identity": {
                "scheme": "Caliptra",
                "ueid": fuses["idevid_cert_attr.ueid"],
                "idevidPublicKey": {"sha256": dice.spki_digest(csr.public_key())},
                "csr": f"identity/{unit}.csr.der",
                "certificate": f"identity/{unit}.idevid.der",
                "endorsingCa": ca_name,
            },
        }
        write_json(art / "provisioning" / f"{unit}.json", log)
        print(f"provision: {unit} IDevID {log['identity']['idevidPublicKey']['sha256'][:16]}... endorsed")
    sign_provisioning(bundle, keys / f"{station['signer']}.key.pem")


def prov_att(unit):
    return f"prov-{unit}.intoto.json"


def sign_provisioning(bundle, key):
    """One fw-provisioning record per unit, from the station's logs, signed with the site key."""
    bundle = Path(bundle)
    art = bundle / "artifacts"
    rel_rd = env_rd(bundle, att_name("release"))
    final = payload(bundle / "att" / att_name("release"))["subject"][0]
    signer = load_signer(key)
    for path in sorted((art / "provisioning").glob("*.json")):
        log = read_json(path)
        unit, ident = log["unit"], log["identity"]
        fuses = log["fuses"]
        expected = {
            "vendorPkHash": fuses["vendor_pk_hash"],
            "ownerPkHash": fuses["owner_pk_hash"],
            "fwSvnFuse": fuses["fw_svn"],
            "pqcKeyType": fuses["fuse_pqc_key_type"],
            "lifecycle": fuses["life_cycle"],
        }
        image = log["images"][0]
        checks = [
            check("image-provenance-verified", image["provenanceVerified"]),
            check("image-readback", image["readback"]["sha256"] == image["digest"]["sha256"]),
            check("fuse-readback", log["fuseReadback"]["sha256"] == canonical_digest(expected)),
            check("csr-self-signature", x509.load_der_x509_csr((art / ident["csr"]).read_bytes()).is_signature_valid),
            check("lifecycle-production", fuses["life_cycle"] == "production" and fuses["debug_locked"]),
        ]
        pred = {
            "buildDefinition": {
                "buildType": PROVISION_TYPE,
                "externalParameters": {"unit": unit, "lotId": log["lotId"], "stage": log["stage"]},
                "resolvedDependencies": [
                    env_rd(bundle, FW_ATT["bundle"]),
                    file_rd(art / IMAGES["bundle"]),
                    file_rd(art / ident["csr"], ident["csr"]),
                    file_rd(art / ident["certificate"], ident["certificate"]),
                ],
            },
            "runDetails": {
                "builder": {"id": f"urn:hslsa:site:{log['station']['site']['name'].lower().replace(' ', '-')}"},
                "metadata": {"invocationId": f"provision:{unit}", "finishedOn": now()},
            },
            "hwProvision": {
                "station": log["station"]["id"],
                "site": log["station"]["site"],
                "unit": f"urn:hslsa:unit:{unit}",
                "lot": f"urn:hslsa:lot:{log['lotId']}",
                "designRef": {"name": final["name"], "digest": final["digest"], "release": rel_rd},
                "images": log["images"],
                "fuses": fuses,
                "secrets": log["secrets"],
                "identity": {
                    **{k: ident[k] for k in ("scheme", "ueid", "idevidPublicKey", "endorsingCa")},
                    "certificate": file_rd(art / ident["certificate"], ident["certificate"]),
                },
                "checks": checks,
            },
        }
        subject = [rd(f"urn:hslsa:unit:{unit}", ident["idevidPublicKey"]["sha256"])]
        sign(statement(subject, FW_PROVISIONING, pred), signer, bundle / "att" / prov_att(unit))
        failed = [c["name"] for c in checks if c["result"] != "pass"]
        if failed:
            raise SystemExit(f"provisioning {unit}: {', '.join(failed)} failed (recorded in the attestation)")
    print(f"provisioning: {len(list((art / 'provisioning').glob('*.json')))} records signed")


# HBOM


FLOW_ENUM = {"source-freeze": "other", "lint": "lint", "rom-merge": "rom-merge", "release": "release"}


def hbom(bundle, lock_path, scenario_path, key):
    bundle = Path(bundle)
    art = bundle / "artifacts"
    lock, sc = read_json(lock_path), read_json(scenario_path)

    def ref(path):
        return {"uri": f"file:{path}", "digest": file_rd(bundle / path)["digest"]}

    flow = []
    for step in ["source-freeze", "lint", "rom-merge", "release"]:
        hw = payload(bundle / "att" / att_name(step))["predicate"]["hwFlow"]
        tools = [{k: t[k] for k in ("name", "version", "digest")} for t in hw["tools"]]
        flow.append(
            {
                "step": FLOW_ENUM[step],
                "tools": tools or [{"name": "hslsa", "version": "0.1"}],
                "provenanceRef": ref(f"att/{att_name(step)}"),
            }
        )
    final = payload(bundle / "att" / att_name("release"))["subject"][0]
    shipped = read_units(art / "shipped-lot.txt")
    fab_sc, pkg, ft, sort = sc["fab"], sc["packaging"], sc["finalTest"], sc["sort"]
    rtl, abr = lock["caliptraRtl"], lock["adamsBridge"]

    def fw(name, role, storage, image, version):
        return {
            "name": name,
            "version": version,
            "role": role,
            "storage": storage,
            "digest": rd2(art / IMAGES[image])["digest"],
            "sbomRef": ref(f"artifacts/sbom-{image}.cdx.json"),
        }

    tag = lock["caliptraSw"]["tag"]
    predicate_ = {
        "hbomVersion": "0.1",
        "product": sc["product"],
        "design": {
            "ipBlocks": [
                {
                    "name": "caliptra-rtl",
                    "kind": "soft",
                    "supplier": {"name": "CHIPS Alliance"},
                    "license": "Apache-2.0",
                    "source": {"uri": rtl["repo"], "digest": {"gitCommit": rtl["commit"]}},
                },
                {
                    "name": "adams-bridge",
                    "kind": "soft",
                    "supplier": {"name": "CHIPS Alliance"},
                    "license": "Apache-2.0",
                    "source": {"uri": abr["repo"], "digest": {"gitCommit": abr["commit"]}},
                },
            ],
            "rtlSources": [
                {"repo": rtl["repo"], "digest": {"gitCommit": rtl["commit"]}, "language": "SystemVerilog"},
                {"repo": abr["repo"], "digest": {"gitCommit": abr["commit"]}, "language": "SystemVerilog"},
            ],
            "flow": flow,
            "finalLayout": {"uri": f"file:artifacts/{final['name']}", "digest": final["digest"]},
        },
        "manufacturing": {
            "fab": {
                "foundry": fab_sc["site"],
                "processNode": fab_sc["processNode"],
                "maskSetId": fab_sc["maskSetId"],
                "attestationRef": ref(f"att/{ATT['wafer-fab']}"),
            },
            "waferLots": [{"lotId": sc["waferLot"]["lotId"], "waferIds": sc["waferLot"]["wafers"]}],
            "assembly": {
                "osat": pkg["site"],
                "packageType": pkg["packageType"],
                "assemblyLot": pkg["assemblyLot"],
                "attestationRef": ref(f"att/{ATT['packaging']}"),
            },
            "test": [
                {
                    "stage": "wafer-sort",
                    "site": sort["site"],
                    "program": sort["program"],
                    "resultsRef": ref(f"att/{ATT['wafer-sort']}"),
                },
                {
                    "stage": "final-test",
                    "site": ft["site"],
                    "program": ft["program"],
                    "resultsRef": ref(f"att/{ATT['final-test']}"),
                },
            ],
        },
        "firmware": [
            fw("caliptra-rom", "boot-rom", "mask-rom", "rom", tag),
            fw("caliptra-fmc", "bootloader", "external-flash", "fmc", tag),
            fw("caliptra-runtime", "runtime", "external-flash", "runtime", tag),
        ],
    }
    hbom_mod.validate(predicate_)
    subjects = [rd(final["name"], final["digest"]["sha256"]), rd(f"urn:hslsa:lot:{ft['lotId']}", lot_digest(shipped))]
    sign(statement(subjects, HBOM, predicate_), load_signer(key), bundle / "att" / "hbom.intoto.json")
    print(f"hbom: signed, {len(flow)} flow steps, {len(predicate_['firmware'])} firmware images, {len(shipped)} units")


# Buyer: Firmware track and the at-boot check


def open_fw(bundle, trust, which):
    label = f"firmware {which}"
    stmt = trust.open(Path(bundle) / "att" / FW_ATT[which], "firmware-platform", SLSA_PROVENANCE)
    if stmt["predicate"]["buildDefinition"]["buildType"] != FW_BUILD_TYPE:
        fail(f"{label}: wrong buildType")
    as_slsa_provenance(stmt, label)
    require_files(bundle, stmt, label)
    for b in stmt["predicate"]["runDetails"].get("byproducts", []):
        if b["name"].startswith("sbom-"):
            path = Path(bundle) / "artifacts" / b["name"]
            if not path.exists() or sha256_file(path) != b["digest"]["sha256"]:
                fail(f"{label}: SBOM {b['name']} is missing or does not match its digest")
    return stmt


def firmware_check(bundle, trust, policy):
    """Firmware L1 and L2 image checks: provenance, SBOMs, the frozen ROM, and the ROM merge that put it in silicon."""
    bundle = Path(bundle)
    pol = policy["firmware"]
    rom = open_fw(bundle, trust, "rom")
    fw = open_fw(bundle, trust, "bundle")
    rom_image = rom["subject"][0]
    if rom_image["digest"].get("sha384") != pol["romSha384"]:
        fail("firmware rom: image is not the ROM the Caliptra TAC froze")
    subjects = {s["name"]: s for s in fw["subject"]}
    for name in (IMAGES["bundle"], IMAGES["fmc"], IMAGES["runtime"]):
        if name not in subjects:
            fail(f"firmware bundle: provenance does not name {name}")
    if not any(s["name"].startswith("sbom-") for s in fw["predicate"]["runDetails"]["byproducts"]):
        fail("firmware bundle: no SBOM")
    byproducts = fw["predicate"]["runDetails"]["byproducts"]
    manifest_rd = next((b for b in byproducts if b["name"] == "fw-manifest.json"), None)
    if not manifest_rd or file_rd(bundle / "artifacts" / "fw-manifest.json")["digest"] != manifest_rd["digest"]:
        fail("firmware bundle: fw-manifest.json does not match its provenance")
    manifest = read_json(bundle / "artifacts" / "fw-manifest.json")
    for image in ("fmc", "runtime"):
        if manifest[image]["sha384"] != subjects[IMAGES[image]]["digest"]["sha384"]:
            fail(f"firmware bundle: manifest {image} digest differs from the provenance subject")
    if manifest["svn"] != fw["predicate"]["buildDefinition"]["externalParameters"]["fwSvn"]:
        fail("firmware bundle: manifest SVN differs from the provenance")
    if manifest["vendorPkHash"] != pol["vendorPkHash"]:
        fail("firmware bundle: signed with vendor keys the policy does not allow")

    # The mask ROM is covered only through the Design track: the ROM merge step must consume this image.
    merge = payload(bundle / "att" / att_name("rom-merge"))
    deps = merge["predicate"]["buildDefinition"]["resolvedDependencies"]
    got = {d["digest"].get("sha256") for d in deps}
    if rom_image["digest"]["sha256"] not in got or env_rd(bundle, FW_ATT["rom"])["digest"]["sha256"] not in got:
        fail("rom-merge: does not consume the ROM image named by its firmware provenance")

    # The HBOM lists the same images, each with its SBOM.
    hb = trust.open(bundle / "att" / "hbom.intoto.json", "product-owner", HBOM)["predicate"]
    listed = {f["name"]: f for f in hb.get("firmware", [])}
    for name, image in (("caliptra-rom", rom_image), ("caliptra-fmc", subjects[IMAGES["fmc"]]),
                        ("caliptra-runtime", subjects[IMAGES["runtime"]])):  # fmt: skip
        entry = listed.get(name)
        if not entry or entry["digest"].get("sha384") != image["digest"]["sha384"]:
            fail(f"hbom: firmware entry {name} does not match the image with provenance")
        sbom = bundle / entry["sbomRef"]["uri"].removeprefix("file:")
        if not sbom.exists() or file_rd(sbom)["digest"] != entry["sbomRef"]["digest"]:
            fail(f"hbom: SBOM for {name} does not match its reference")
    return {
        "rom": rom_image,
        "fmc": subjects[IMAGES["fmc"]],
        "runtime": subjects[IMAGES["runtime"]],
        "bundle": subjects[IMAGES["bundle"]],
        "manifest": manifest,
        "inputs": [env_rd(bundle, FW_ATT["rom"]), env_rd(bundle, FW_ATT["bundle"])],
    }


def fuse_info_digests(fuses, manifest):
    """What the ROM measures about its fuses (CALIPTRA_2_X_FUSE_OWNER_INFO and _VENDOR_INFO TcbInfo)."""
    fw_svn_bits = fuses["fw_svn"]
    owner = (
        bytes.fromhex(fuses["owner_pk_hash"])
        + bytes([1, int(fuses["anti_rollback_disable"]), fuses["fuse_ecc_revocation"]])
        + fuses["fuse_lms_revocation"].to_bytes(4, "little")
        + bytes([fuses["fuse_mldsa_revocation"], fw_svn_bits, fuses["soc_manifest_svn"], fuses["soc_manifest_max_svn"]])
    )
    vendor = bytes.fromhex(fuses["vendor_pk_hash"]) + bytes(
        [
            fuses["fuse_pqc_key_type"],
            LIFECYCLE[fuses["life_cycle"]],
            int(fuses["debug_locked"]),
            manifest["svn"],
            manifest["vendorEccKeyIndex"],
            manifest["vendorPqcKeyIndex"],
            0,  # passive mode, not subsystem mode
        ]
    )
    return sha384_bytes(owner), sha384_bytes(vendor)


def fwid(tcb, label):
    ids = [f for f in tcb["fwids"] if f["hashAlg"] == dice.SHA384_OID]
    if len(ids) != 1:
        fail(f"{label}: expected one SHA-384 FWID")
    return ids[0]["digest"]


def device_check(bundle, trust, policy, design, lot, fw, unit, boot_dir):
    """The spec's at-boot check for one unit, from what the booted device returned."""
    bundle, boot_dir = Path(bundle), Path(boot_dir)
    art = bundle / "artifacts"
    label = f"device {unit}"
    certs = {}
    for name in ("ldevid", "fmc-alias", "rt-alias"):
        path = boot_dir / f"{name}-ecc384.der"
        if not path.exists():
            fail(f"{label}: no {name} certificate from the device")
        certs[name] = dice.load_cert(path)

    # The identity the device proves names the unit, and the unit is in the shipped lot.
    want = (1, unit.encode().ljust(16, b"\0"))
    for name, cert in certs.items():
        if dice.ueid(cert) != want:
            fail(f"{label}: UEID in the {name} certificate does not name this unit")
    shipped = read_units(art / "shipped-lot.txt")
    if unit not in shipped:
        fail(f"{label}: unit is not in the shipped lot")

    # 2. The provisioning record for this unit, signed by the site that programmed it.
    station = policy["firmware"]["provisioningSigner"]
    rec = trust.open(bundle / "att" / prov_att(unit), station, FW_PROVISIONING)
    if rec["predicate"]["buildDefinition"]["buildType"] != PROVISION_TYPE:
        fail(f"{label}: provisioning record has the wrong buildType")
    as_slsa_provenance(rec, f"{label} provisioning")
    hp = rec["predicate"]["hwProvision"]
    failed = [c["name"] for c in hp["checks"] if c["result"] != "pass"]
    if failed:
        fail(f"{label}: provisioning gate failed: {', '.join(failed)}")
    if hp["unit"] != f"urn:hslsa:unit:{unit}" or rec["subject"][0]["name"] != hp["unit"]:
        fail(f"{label}: provisioning record is for {hp['unit']}")
    if hp["lot"] != lot["lot"]["name"]:
        fail(f"{label}: provisioning record names lot {hp['lot']}")
    if hp["designRef"]["digest"] != design["final"]["digest"] or hp["designRef"]["release"] != design["release"]:
        fail(f"{label}: provisioning record names a different design release")

    # 1. Certificate chain: identity CA -> IDevID -> LDevID -> FMC alias -> RT alias.
    ident = hp["identity"]
    cert_path = art / ident["certificate"]["name"]
    if not cert_path.exists() or file_rd(cert_path)["digest"] != ident["certificate"]["digest"]:
        fail(f"{label}: IDevID certificate does not match the provisioning record")
    idevid = dice.load_cert(cert_path)
    ca_keys = [serialization.load_pem_public_key(k.keyval["public"].encode()) for k in trust.roles["identity-ca"]]
    if not any(_verifies(idevid, k) for k in ca_keys):
        fail(f"{label}: IDevID certificate is not endorsed by the identity CA")
    if dice.spki_digest(idevid.public_key()) != rec["subject"][0]["digest"]["sha256"]:
        fail(f"{label}: provisioning record subject is not this IDevID key")
    for child, parent, name in (
        (certs["ldevid"], idevid, "LDevID"),
        (certs["fmc-alias"], certs["ldevid"], "FMC alias"),
        (certs["rt-alias"], certs["fmc-alias"], "RT alias"),
    ):
        dice.check_signed_by(child, parent.public_key(), parent.subject, f"{label} {name}")

    # 3. Every measurement matches an image with provenance.
    fmc_tcb = dice.tcb_info_of_type(certs["fmc-alias"], "CALIPTRA_2_X_FMC_FIRMWARE_INFO", label)
    rt_tcb = dice.tcb_info_of_type(certs["rt-alias"], "CALIPTRA_2_X_RT_FIRMWARE_INFO", label)
    if fwid(fmc_tcb, label) != fw["fmc"]["digest"]["sha384"]:
        fail(f"{label}: FMC measurement matches no FMC image with provenance")
    if fwid(rt_tcb, label) != fw["runtime"]["digest"]["sha384"]:
        fail(f"{label}: runtime measurement matches no runtime image with provenance")
    images = {i["name"]: i for i in hp["images"]}
    if images.get(IMAGES["bundle"], {}).get("digest") != fw["bundle"]["digest"]:
        fail(f"{label}: provisioning record wrote a different firmware bundle")

    # The device measured the fuses the station says it burned.
    fuses = hp["fuses"]
    owner, vendor = fuse_info_digests(fuses, fw["manifest"])
    if fwid(dice.tcb_info_of_type(certs["fmc-alias"], "CALIPTRA_2_X_FUSE_VENDOR_INFO", label), label) != vendor:
        fail(f"{label}: vendor fuses the device measured differ from the provisioning record")
    if fwid(dice.tcb_info_of_type(certs["fmc-alias"], "CALIPTRA_2_X_FUSE_OWNER_INFO", label), label) != owner:
        fail(f"{label}: owner fuses the device measured differ from the provisioning record")
    if fuses["vendor_pk_hash"] != policy["firmware"]["vendorPkHash"]:
        fail(f"{label}: vendor key hash fuse is not the policy's")
    if fuses["life_cycle"] != "production" or not fuses["debug_locked"]:
        fail(f"{label}: unit is not in the production lifecycle with debug locked")

    # 5. Anti-rollback: the running SVN is the image's, and not below the fuse.
    svn = fw["manifest"]["svn"]
    for tcb in (fmc_tcb, rt_tcb):
        if tcb.get("svn", 0) & 0xFF != svn:
            fail(f"{label}: device reports SVN {tcb.get('svn', 0) & 0xFF}, image provenance says {svn}")
    if svn < fuses["fw_svn"] or svn < policy["firmware"]["minSvn"]:
        fail(f"{label}: image SVN {svn} is below the anti-rollback fuse or policy minimum")

    # 4. The ROM that took the first measurement is covered by the design chain (checked in firmware_check).
    return {
        "unit": rd(f"urn:hslsa:unit:{unit}", sha256_file(cert_path)),
        "inputs": [env_rd(bundle, prov_att(unit))],
    }


def _verifies(cert, key):
    try:
        key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        return True
    except Exception:
        return False


def verify(bundle, trust, policy_path, units_path, boots_dir, vsa_key=None, vsa_dir=None):
    bundle = Path(bundle)
    policy = read_json(policy_path)
    design = tapeout_check(bundle, trust, policy)
    print(f"tapeout check: PASSED for {design['final']['name']} sha256:{design['final']['digest']['sha256']}")
    units = read_units(units_path)
    lot = lot_check(bundle, trust, policy, design, units)
    print(f"lot receipt check: PASSED for {lot['lot']['name']}, {len(units)} received units found in the lot")
    fw = firmware_check(bundle, trust, policy)
    print(f"firmware check: PASSED, ROM is the TAC-frozen image, FMC and runtime svn {fw['manifest']['svn']}")
    devices = [device_check(bundle, trust, policy, design, lot, fw, u, Path(boots_dir) / u) for u in units]
    print(f"at-boot check: PASSED for {len(devices)} booted units ({', '.join(units)})")
    if vsa_key:
        out = Path(vsa_dir)
        claims = policy["claims"]
        vsa(design["final"], f"hslsa:design:{design['final']['name']}", claims["design"],
            [design["release"]] + design["inputs"], policy_path, vsa_key, out / "design.vsa.intoto.json")  # fmt: skip
        vsa(lot["lot"], lot["lot"]["name"], claims["lot"], lot["inputs"] + [design["release"]],
            policy_path, vsa_key, out / "lot.vsa.intoto.json")  # fmt: skip
        fw_subject = {"name": fw["bundle"]["name"], "digest": {"sha256": fw["bundle"]["digest"]["sha256"]}}
        vsa(fw_subject, f"hslsa:firmware:{fw['bundle']['name']}", claims["firmware"], fw["inputs"],
            policy_path, vsa_key, out / "firmware.vsa.intoto.json")  # fmt: skip
        for unit, dev in zip(units, devices, strict=True):
            vsa(dev["unit"], dev["unit"]["name"], claims["device"],
                dev["inputs"] + fw["inputs"] + lot["inputs"] + [design["release"]],
                policy_path, vsa_key, out / f"device-{unit}.vsa.intoto.json")  # fmt: skip
        print(f"VSAs written to {out}: design, lot, firmware and {len(devices)} devices")
    return design, lot, fw, devices
