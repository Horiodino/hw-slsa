"""DICE certificate helpers: TCG TcbInfo and UEID extensions, and chain signature checks.

Only what the at-boot check needs. The extensions are parsed with a small DER
reader so no ASN.1 library is required beyond `cryptography`.
"""

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .common import VerificationError, sha256_bytes

TCB_INFO = x509.ObjectIdentifier("2.23.133.5.4.1")
MULTI_TCB_INFO = x509.ObjectIdentifier("2.23.133.5.4.5")
UEID = x509.ObjectIdentifier("2.23.133.5.4.4")
SHA384_OID = "2.16.840.1.101.3.4.2.2"


def tlv(data, pos=0):
    """One DER element at pos: (tag, value bytes, position after it)."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    return tag, data[pos : pos + length], pos + length


def children(data):
    pos, out = 0, []
    while pos < len(data):
        tag, value, pos = tlv(data, pos)
        out.append((tag, value))
    return out


def oid_str(value):
    first = value[0]
    parts, n = [first // 40, first % 40], 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def parse_tcb_info(value):
    """DiceTcbInfo (TCG DICE Attestation Architecture): the fields the verifier uses."""
    info = {"fwids": []}
    for tag, v in children(value):
        field = tag & 0x1F
        if field == 0:
            info["vendor"] = v.decode()
        elif field == 1:
            info["model"] = v.decode()
        elif field == 3:
            info["svn"] = int.from_bytes(v, "big")
        elif field == 6:
            for _, fwid in children(v):
                (_, alg), (_, digest) = children(fwid)
                info["fwids"].append({"hashAlg": oid_str(alg), "digest": digest.hex()})
        elif field == 9:
            info["type"] = v.decode(errors="replace")
    return info


def tcb_infos(cert):
    """Every TcbInfo in a certificate, from the single and the multi-TcbInfo extensions."""
    out = []
    for ext in cert.extensions:
        if ext.oid == TCB_INFO:
            _, value, _ = tlv(ext.value.value)
            out.append(parse_tcb_info(value))
        elif ext.oid == MULTI_TCB_INFO:
            _, seq, _ = tlv(ext.value.value)
            out += [parse_tcb_info(v) for _, v in children(seq)]
    return out


def tcb_info_of_type(cert, kind, label):
    found = [t for t in tcb_infos(cert) if t.get("type") == kind]
    if len(found) != 1:
        raise VerificationError(f"{label}: expected one TcbInfo of type {kind}, found {len(found)}")
    return found[0]


def ueid(cert):
    """The TCG UEID extension: (type byte, the 16 bytes after it)."""
    try:
        ext = cert.extensions.get_extension_for_oid(UEID)
    except x509.ExtensionNotFound:
        return None
    _, seq, _ = tlv(ext.value.value)
    _, raw, _ = tlv(seq)
    return raw[0], raw[1:]


def load_cert(path):
    return x509.load_der_x509_certificate(path.read_bytes())


def spki_digest(public_key):
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256_bytes(der)


def check_signed_by(cert, issuer_key, issuer_name, label):
    """cert carries a valid ECDSA signature from issuer_key and names issuer_name as its issuer."""
    if cert.issuer != issuer_name:
        raise VerificationError(f"{label}: issuer {cert.issuer.rfc4514_string()} is not the expected parent")
    try:
        issuer_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    except InvalidSignature as e:
        raise VerificationError(f"{label}: signature does not verify under the parent key") from e


def check_csr(csr, label):
    if not csr.is_signature_valid:
        raise VerificationError(f"{label}: CSR self-signature is invalid")
