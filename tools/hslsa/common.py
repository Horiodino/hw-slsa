"""Shared helpers: digests, in-toto statements, DSSE signing and the trust root."""

import datetime
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from google.protobuf import json_format
from in_toto_attestation.v1 import statement_pb2
from in_toto_attestation.v1.statement import Statement
from securesystemslib.dsse import Envelope
from securesystemslib.signer import CryptoSigner, SSlibKey

NS = "https://github.com/Horiodino/hw-slsa"
DESIGN_FLOW = f"{NS}/design-flow/v0.1"
MFG_STEP = f"{NS}/manufacturing-step/v0.1"
HBOM = f"{NS}/hbom/v0.1"
VSA = "https://slsa.dev/verification_summary/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"


def design_step_type(step):
    return f"{NS}/design-flow/step/{step}@v1"


def mfg_step_type(step):
    return f"{NS}/mfg/step/{step}@v1"


class VerificationError(Exception):
    pass


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    return sha256_bytes(Path(path).read_bytes())


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def read_json(path):
    return json.loads(Path(path).read_text())


def rd(name, digest, **extra):
    """An in-toto ResourceDescriptor with a sha256 digest."""
    return {"name": name, "digest": {"sha256": digest}, **extra}


def file_rd(path, name=None):
    path = Path(path)
    return rd(name or path.name, sha256_file(path))


def builder():
    """Identity of the platform running this step, taken from GitHub Actions when present."""
    server = os.environ.get("GITHUB_SERVER_URL")
    if server and os.environ.get("GITHUB_WORKFLOW_REF"):
        run = f"{server}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
        return {
            "builder": {"id": f"{server}/{os.environ['GITHUB_WORKFLOW_REF']}"},
            "metadata": {"invocationId": f"{run}/attempts/{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}"},
        }
    return {"builder": {"id": f"{NS}/local-run"}, "metadata": {"invocationId": "local"}}


def statement(subjects, predicate_type, predicate):
    stmt = {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": predicate_type,
        "predicate": predicate,
    }
    validate_statement(stmt)
    return stmt


def validate_statement(stmt):
    """Structural check with the in-toto attestation reference library."""
    pb = statement_pb2.Statement()
    json_format.ParseDict(stmt, pb)
    try:
        Statement.copy_from_pb(pb).validate()
    except ValueError as e:
        raise VerificationError(f"invalid in-toto statement: {e}") from e


# Keys and signing


def keygen(out_dir, role):
    signer = CryptoSigner.generate_ecdsa()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{role}.key.pem").write_bytes(signer.private_bytes)
    (out_dir / f"{role}.key.pem").chmod(0o600)
    (out_dir / f"{role}.pub.pem").write_text(signer.public_key.keyval["public"])
    return signer


def load_signer(path):
    return CryptoSigner(load_pem_private_key(Path(path).read_bytes(), password=None))


def public_key_from_pem(pem):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    return SSlibKey.from_crypto(load_pem_public_key(pem.encode()))


def sign(stmt, signer, path):
    """Sign a statement into a DSSE envelope and write it to path."""
    validate_statement(stmt)
    payload = json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode()
    env = Envelope(payload=payload, payload_type=PAYLOAD_TYPE, signatures={})
    env.sign(signer)
    write_json(path, env.to_dict())
    return rd(Path(path).name, sha256_file(path))


class TrustRoot:
    """Which public keys may sign for which role.

    File format: {"roles": {"<role>": ["<PEM public key>", ...]}}
    """

    def __init__(self, data):
        self.roles = {role: [public_key_from_pem(pem) for pem in pems] for role, pems in data["roles"].items()}

    @classmethod
    def load(cls, path):
        return cls(read_json(path))

    @staticmethod
    def build(pub_dir, out_path):
        roles = {}
        for pub in sorted(Path(pub_dir).glob("*.pub.pem")):
            roles.setdefault(pub.name[: -len(".pub.pem")], []).append(pub.read_text())
        write_json(out_path, {"roles": roles})

    def open(self, path, role, predicate_type=None):
        """Verify an envelope was signed by `role` and return its statement."""
        path = Path(path)
        if not path.exists():
            raise VerificationError(f"missing attestation {path.name}")
        env = Envelope.from_dict(read_json(path))
        if env.payload_type != PAYLOAD_TYPE:
            raise VerificationError(f"{path.name}: unexpected payload type {env.payload_type}")
        keys = self.roles.get(role, [])
        try:
            env.verify(keys, 1)
        except Exception as e:  # securesystemslib raises VerificationError subclasses
            raise VerificationError(f"{path.name}: no valid signature from role '{role}'") from e
        stmt = json.loads(env.payload)
        validate_statement(stmt)
        if predicate_type and stmt["predicateType"] != predicate_type:
            raise VerificationError(f"{path.name}: predicate type {stmt['predicateType']}, want {predicate_type}")
        return stmt
