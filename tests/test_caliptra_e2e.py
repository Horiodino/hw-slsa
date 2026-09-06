"""Tamper tests for the Caliptra example: every broken link from RTL to a booted device must fail, for the right reason.

Needs the output of `e2e/caliptra/run.sh produce` and `verify` (HSLSA_CALIPTRA_OUT,
default out/caliptra): the bundle, and the certificates the booted units returned.
As in test_e2e.py, the producer keys never leave the produce job, so the fixture
re-signs every record with fresh test keys, and endorses the units' IDevID CSRs
with a fresh identity CA. Tests can then forge validly signed lies.
"""

import base64
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hslsa import caliptra, mfg
from hslsa.common import TrustRoot, VerificationError, keygen, load_signer, read_json, sign, write_json
from hslsa.design import att_name
from hslsa.lot import read_units

ROOT = Path(__file__).resolve().parents[1]
E2E = ROOT / "e2e" / "caliptra"
LOCK, SCENARIO, POLICY = E2E / "caliptra.lock.json", E2E / "mfg-scenario.json", E2E / "policy.json"
SOURCE = Path(os.environ.get("HSLSA_CALIPTRA_OUT", ROOT / "out" / "caliptra"))
ROLES = [
    "flow-platform",
    "tapeout-authority",
    "firmware-platform",
    "fab-site",
    "sort-site",
    "osat-site",
    "test-site",
    "product-owner",
]
UNIT, OTHER = "CLP-00002", "CLP-00005"

needs_run = pytest.mark.skipif(
    not (SOURCE / "bundle" / "att").exists() or not (SOURCE / "boots").exists(),
    reason="run e2e/caliptra/run.sh produce and verify first",
)


def decode(path):
    return json.loads(base64.b64decode(read_json(path)["payload"]))


def resign(bundle, name, role, mutate=lambda s: None):
    path = bundle / "att" / name
    stmt = decode(path)
    mutate(stmt)
    sign(stmt, load_signer(bundle.parent / "keys" / f"{role}.key.pem"), path)


def reendorse(bundle, ca_key_path):
    ca_key = serialization.load_pem_private_key(Path(ca_key_path).read_bytes(), password=None)
    art = bundle / "artifacts" / "identity"
    for csr_path in sorted(art.glob("*.csr.der")):
        csr = x509.load_der_x509_csr(csr_path.read_bytes())
        cert = caliptra.endorse(csr, ca_key, "HSLSA Test IDevID CA")
        unit = csr_path.name.removesuffix(".csr.der")
        (art / f"{unit}.idevid.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))


def rebuild(bundle, from_rom_merge=True):
    """Re-sign the chain downstream of the design steps and firmware provenance with the test keys."""
    keys = bundle.parent / "keys"
    if from_rom_merge:
        rom_env = caliptra.env_rd(bundle, caliptra.FW_ATT["rom"])

        def relink(s):
            for d in s["predicate"]["buildDefinition"]["resolvedDependencies"]:
                if d["name"] == rom_env["name"]:
                    d["digest"] = rom_env["digest"]

        resign(bundle, att_name("rom-merge"), "flow-platform", relink)
    caliptra.release(bundle, keys / "tapeout-authority.key.pem", bundle / "trust-root.json", POLICY)
    mfg.run(bundle, SCENARIO, keys)
    caliptra.sign_provisioning(bundle, keys / "test-site.key.pem")
    caliptra.hbom(bundle, LOCK, SCENARIO, keys / "product-owner.key.pem")


def ca_key(keys, name):
    key = ec.generate_private_key(ec.SECP384R1())
    (keys / f"{name}.key.pem").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return key


@pytest.fixture(scope="session")
def valid(tmp_path_factory):
    work = tmp_path_factory.mktemp("caliptra")
    bundle = work / "bundle"
    shutil.copytree(SOURCE / "bundle", bundle)
    shutil.copytree(SOURCE / "boots", work / "boots")
    keys, pub = work / "keys", work / "pub"
    pub.mkdir()
    for role in ROLES + ["attacker"]:
        keygen(keys, role)
    for role in ROLES:
        shutil.copy(keys / f"{role}.pub.pem", pub)
    ca = ca_key(keys, "identity-ca")
    ca_key(keys, "attacker-ca")
    (pub / "identity-ca.pub.pem").write_bytes(
        ca.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    TrustRoot.build(pub, bundle / "trust-root.json")
    for name in caliptra.FW_ATT.values():
        resign(bundle, name, "firmware-platform")
    for step in ["source-freeze", "lint"]:
        resign(bundle, att_name(step), "flow-platform")
    reendorse(bundle, keys / "identity-ca.key.pem")
    rebuild(bundle)
    return work


@pytest.fixture
def work(valid, tmp_path):
    shutil.copytree(valid, tmp_path / "w")
    return tmp_path / "w"


def check(work, units=None, policy=POLICY):
    bundle = work / "bundle"
    units_file = work / "units.txt"
    units_file.write_text("\n".join(units or read_units(E2E / "received-units.txt")) + "\n")
    trust = TrustRoot.load(bundle / "trust-root.json")
    return caliptra.verify(bundle, trust, policy, units_file, work / "boots")


def rejects(work, reason, **kw):
    with pytest.raises(VerificationError) as err:
        check(work, **kw)
    assert reason in str(err.value)


@needs_run
def test_produced_run_verifies_as_is():
    check(SOURCE)


@needs_run
def test_rebuilt_bundle_verifies(work):
    check(work)


# The device


@needs_run
def test_certificate_from_another_unit(work):
    shutil.copy(work / "boots" / OTHER / "ldevid-ecc384.der", work / "boots" / UNIT / "ldevid-ecc384.der")
    rejects(work, f"device {UNIT}: UEID in the ldevid certificate does not name this unit")


@needs_run
def test_missing_alias_certificate(work):
    (work / "boots" / UNIT / "rt-alias-ecc384.der").unlink()
    rejects(work, f"device {UNIT}: no rt-alias certificate from the device")


@needs_run
def test_ldevid_not_signed_by_idevid(work):
    """An LDevID certificate with the right names and serial, signed by a key that is not the unit's IDevID."""
    path = work / "boots" / UNIT / "ldevid-ecc384.der"
    real = x509.load_der_x509_certificate(path.read_bytes())
    b = (
        x509.CertificateBuilder()
        .subject_name(real.subject)
        .issuer_name(real.issuer)
        .public_key(real.public_key())
        .serial_number(real.serial_number)
        .not_valid_before(real.not_valid_before_utc)
        .not_valid_after(datetime(9999, 12, 31, tzinfo=timezone.utc))
    )
    for ext in real.extensions:
        b = b.add_extension(ext.value, ext.critical)
    path.write_bytes(b.sign(ec.generate_private_key(ec.SECP384R1()), hashes.SHA384()).public_bytes(
        serialization.Encoding.DER))  # fmt: skip
    rejects(work, f"device {UNIT} LDevID: signature does not verify under the parent key")


@needs_run
def test_received_unit_that_failed_final_test(work):
    rejects(work, "received unit CLP-00006 is not in the shipped lot", units=[UNIT, "CLP-00006"])


# Provisioning and identity


@needs_run
def test_provisioning_record_of_another_unit(work):
    att = work / "bundle" / "att"
    shutil.copy(att / caliptra.prov_att(OTHER), att / caliptra.prov_att(UNIT))
    rejects(work, f"provisioning record is for urn:hslsa:unit:{OTHER}")


@needs_run
def test_provisioning_record_signed_by_another_site(work):
    resign(work / "bundle", caliptra.prov_att(UNIT), "osat-site")
    rejects(work, "no valid signature from role 'test-site'")


@needs_run
def test_provisioning_record_edited_without_resigning(work):
    path = work / "bundle" / "att" / caliptra.prov_att(UNIT)
    env = read_json(path)
    stmt = json.loads(base64.b64decode(env["payload"]))
    stmt["predicate"]["hwProvision"]["fuses"]["fw_svn"] = 0
    env["payload"] = base64.b64encode(json.dumps(stmt).encode()).decode()
    write_json(path, env)
    rejects(work, "no valid signature from role 'test-site'")


@needs_run
def test_idevid_endorsed_by_another_ca(work):
    reendorse(work / "bundle", work / "keys" / "attacker-ca.key.pem")
    caliptra.sign_provisioning(work / "bundle", work / "keys" / "test-site.key.pem")
    rejects(work, f"device {UNIT}: IDevID certificate is not endorsed by the identity CA")


@needs_run
def test_record_claims_other_vendor_fuses(work):
    def other(s):
        s["predicate"]["hwProvision"]["fuses"]["vendor_pk_hash"] = "ab" * 48

    resign(work / "bundle", caliptra.prov_att(UNIT), "test-site", other)
    rejects(work, "vendor fuses the device measured differ from the provisioning record")


@needs_run
def test_record_claims_other_svn_fuse(work):
    def other(s):
        s["predicate"]["hwProvision"]["fuses"]["fw_svn"] = 3

    resign(work / "bundle", caliptra.prov_att(UNIT), "test-site", other)
    rejects(work, "owner fuses the device measured differ from the provisioning record")


@needs_run
def test_record_names_another_design(work):
    def other(s):
        s["predicate"]["hwProvision"]["designRef"]["digest"]["sha256"] = "1" * 64

    resign(work / "bundle", caliptra.prov_att(UNIT), "test-site", other)
    rejects(work, "provisioning record names a different design release")


@needs_run
def test_policy_minimum_svn_above_the_image(work, tmp_path):
    policy = read_json(POLICY)
    policy["firmware"]["minSvn"] = 2
    write_json(tmp_path / "policy.json", policy)
    rejects(work, "image SVN 1 is below the anti-rollback fuse or policy minimum", policy=tmp_path / "policy.json")


# Firmware images


@needs_run
def test_firmware_provenance_for_another_fmc(work):
    """Validly signed provenance and manifest for an FMC the device did not run."""
    bundle = work / "bundle"
    fake = "5" * 96
    manifest = read_json(bundle / "artifacts" / "fw-manifest.json")
    manifest["fmc"]["sha384"] = fake
    write_json(bundle / "artifacts" / "fw-manifest.json", manifest)
    manifest_rd = caliptra.file_rd(bundle / "artifacts" / "fw-manifest.json")

    def other(s):
        for subj in s["subject"]:
            if subj["name"] == caliptra.IMAGES["fmc"]:
                subj["digest"]["sha384"] = fake
        for b in s["predicate"]["runDetails"]["byproducts"]:
            if b["name"] == "fw-manifest.json":
                b["digest"] = manifest_rd["digest"]

    def hbom_agrees(s):
        for f in s["predicate"]["firmware"]:
            if f["name"] == "caliptra-fmc":
                f["digest"]["sha384"] = fake

    resign(bundle, caliptra.FW_ATT["bundle"], "firmware-platform", other)
    rebuild(bundle, from_rom_merge=False)
    resign(bundle, "hbom.intoto.json", "product-owner", hbom_agrees)
    # Every record agrees with every other; only the device's own measurement catches the lie.
    rejects(work, f"device {UNIT}: FMC measurement matches no FMC image with provenance")


@needs_run
def test_rom_that_is_not_the_frozen_image(work):
    def other(s):
        s["subject"][0]["digest"]["sha384"] = "6" * 96

    resign(work / "bundle", caliptra.FW_ATT["rom"], "firmware-platform", other)
    rebuild(work / "bundle")
    rejects(work, "firmware rom: image is not the ROM the Caliptra TAC froze")


@needs_run
def test_firmware_signed_by_the_flow_platform(work):
    resign(work / "bundle", caliptra.FW_ATT["bundle"], "flow-platform")
    rejects(work, "no valid signature from role 'firmware-platform'")


@needs_run
def test_sbom_swapped(work):
    with open(work / "bundle" / "artifacts" / "sbom-runtime.cdx.json", "a") as f:
        f.write("\n")
    rejects(work, "SBOM sbom-runtime.cdx.json is missing or does not match its digest")


@needs_run
def test_hbom_lists_another_runtime(work):
    def other(s):
        for f in s["predicate"]["firmware"]:
            if f["name"] == "caliptra-runtime":
                f["digest"]["sha384"] = "7" * 96

    resign(work / "bundle", "hbom.intoto.json", "product-owner", other)
    rejects(work, "hbom: firmware entry caliptra-runtime does not match the image with provenance")


# The mask ROM, through the Design track


@needs_run
def test_rom_merge_does_not_consume_the_rom(work):
    def unlink(s):
        deps = s["predicate"]["buildDefinition"]["resolvedDependencies"]
        s["predicate"]["buildDefinition"]["resolvedDependencies"] = [d for d in deps if d["name"] == caliptra.RTL_TAR]

    resign(work / "bundle", att_name("rom-merge"), "flow-platform", unlink)
    rebuild(work / "bundle", from_rom_merge=False)
    rejects(work, "rom-merge: does not consume the ROM image named by its firmware provenance")


@needs_run
def test_rom_readback_failed(work):
    def fail_readback(s):
        for c in s["predicate"]["hwFlow"]["checks"]:
            if c["name"] == "rom-readback":
                c["result"] = "fail"

    resign(work / "bundle", att_name("rom-merge"), "flow-platform", fail_readback)
    rejects(work, "design rom-merge: gate failed: rom-readback")


@needs_run
def test_released_design_swapped(work):
    with open(work / "bundle" / "artifacts" / caliptra.DESIGN_TAR, "ab") as f:
        f.write(b"\0" * 512)
    rejects(work, f"subject {caliptra.DESIGN_TAR} does not match its attested digest")


@needs_run
def test_lint_failure_recorded(work):
    def fail_lint(s):
        s["predicate"]["hwFlow"]["checks"][0]["result"] = "fail"

    resign(work / "bundle", att_name("lint"), "flow-platform", fail_lint)
    rejects(work, "design lint: gate failed: verilator-lint")


@needs_run
def test_unit_list_tampered(work):
    with open(work / "bundle" / "artifacts" / "shipped-lot.txt", "a") as f:
        f.write("CLP-99999\n")
    rejects(work, "shipped lot list does not match the attested lot digest")


def test_rom_hex_round_trip():
    data = bytes(range(256)) * 3 + b"\x01"
    assert caliptra.read_rom_hex(caliptra.rom_hex(data).decode()) == data


def test_fuse_info_digest_changes_with_every_vendor_fuse():
    manifest = {"svn": 1, "vendorEccKeyIndex": 0, "vendorPqcKeyIndex": 0}
    fuses = caliptra.fuse_map("CLP-00001", {"vendorPkHash": "a" * 96, "ownerPkHash": "b" * 96, "pqcKeyType": 1},
                              "production", 1)  # fmt: skip
    base = caliptra.fuse_info_digests(fuses, manifest)
    for field, value in [("vendor_pk_hash", "c" * 96), ("life_cycle", "manufacturing"), ("debug_locked", False)]:
        assert caliptra.fuse_info_digests({**fuses, field: value}, manifest)[1] != base[1]
    assert caliptra.fuse_info_digests({**fuses, "fw_svn": 2}, manifest)[0] != base[0]
