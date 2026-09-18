package hslsa

// DICE certificate helpers: TCG TcbInfo and UEID extensions, and chain
// signature checks. Only what the at-boot check needs; the extensions are
// read with a small DER reader.

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"crypto/x509/pkix"
)

var (
	oidTcbInfo      = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}
	oidMultiTcbInfo = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 5}
	oidUEID         = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 4}
)

// SHA384OID is the FWID hash algorithm Caliptra uses.
const SHA384OID = "2.16.840.1.101.3.4.2.2"

type derElem struct {
	tag   byte
	value []byte
}

// tlv reads one DER element at pos: its tag, value and the position after it.
func tlv(data []byte, pos int) (byte, []byte, int, error) {
	if pos+2 > len(data) {
		return 0, nil, 0, fmt.Errorf("truncated DER")
	}
	tag, length := data[pos], int(data[pos+1])
	pos += 2
	if length&0x80 != 0 {
		n := length & 0x7f
		if n > 4 || pos+n > len(data) {
			return 0, nil, 0, fmt.Errorf("bad DER length")
		}
		length = 0
		for _, b := range data[pos : pos+n] {
			length = length<<8 | int(b)
		}
		pos += n
	}
	if length < 0 || pos+length > len(data) {
		return 0, nil, 0, fmt.Errorf("truncated DER")
	}
	return tag, data[pos : pos+length], pos + length, nil
}

func derChildren(data []byte) ([]derElem, error) {
	var out []derElem
	for pos := 0; pos < len(data); {
		tag, value, next, err := tlv(data, pos)
		if err != nil {
			return nil, err
		}
		out = append(out, derElem{tag, value})
		pos = next
	}
	return out, nil
}

func oidString(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	parts := []string{fmt.Sprint(value[0] / 40), fmt.Sprint(value[0] % 40)}
	n := new(big.Int)
	for _, b := range value[1:] {
		n.Lsh(n, 7)
		n.Or(n, big.NewInt(int64(b&0x7f)))
		if b&0x80 == 0 {
			parts = append(parts, n.String())
			n = new(big.Int)
		}
	}
	return strings.Join(parts, ".")
}

// FWID is one firmware measurement in a TcbInfo.
type FWID struct {
	HashAlg string
	Digest  string
}

// TcbInfo holds the DiceTcbInfo fields the verifier uses.
type TcbInfo struct {
	Vendor, Model, Type string
	SVN                 int64
	HasSVN              bool
	Layer, Index        *uint64
	FWIDs               []FWID
}

func parseTcbInfo(value []byte) (TcbInfo, error) {
	var info TcbInfo
	fields, err := derChildren(value)
	if err != nil {
		return info, err
	}
	for _, f := range fields {
		switch f.tag & 0x1f {
		case 0:
			info.Vendor = string(f.value)
		case 1:
			info.Model = string(f.value)
		case 3:
			info.SVN = new(big.Int).SetBytes(f.value).Int64()
			info.HasSVN = true
		case 4, 5:
			v := new(big.Int).SetBytes(f.value).Uint64()
			if f.tag&0x1f == 4 {
				info.Layer = &v
			} else {
				info.Index = &v
			}
		case 6:
			fwids, err := derChildren(f.value)
			if err != nil {
				return info, err
			}
			for _, fw := range fwids {
				parts, err := derChildren(fw.value)
				if err != nil || len(parts) != 2 {
					return info, fmt.Errorf("bad FWID")
				}
				info.FWIDs = append(info.FWIDs, FWID{HashAlg: oidString(parts[0].value), Digest: hex.EncodeToString(parts[1].value)})
			}
		case 9:
			info.Type = string(f.value)
		}
	}
	return info, nil
}

// TcbInfos returns every TcbInfo in a certificate, from the single and the multi-TcbInfo extensions.
func TcbInfos(cert *x509.Certificate) ([]TcbInfo, error) {
	var out []TcbInfo
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidTcbInfo):
			_, value, _, err := tlv(ext.Value, 0)
			if err != nil {
				return nil, err
			}
			info, err := parseTcbInfo(value)
			if err != nil {
				return nil, err
			}
			out = append(out, info)
		case ext.Id.Equal(oidMultiTcbInfo):
			_, seq, _, err := tlv(ext.Value, 0)
			if err != nil {
				return nil, err
			}
			items, err := derChildren(seq)
			if err != nil {
				return nil, err
			}
			for _, it := range items {
				info, err := parseTcbInfo(it.value)
				if err != nil {
					return nil, err
				}
				out = append(out, info)
			}
		}
	}
	return out, nil
}

func tcbInfoOfType(cert *x509.Certificate, kind, label string) (TcbInfo, error) {
	all, err := TcbInfos(cert)
	if err != nil {
		return TcbInfo{}, failf("%s: unreadable TcbInfo: %v", label, err)
	}
	var found []TcbInfo
	for _, t := range all {
		if t.Type == kind {
			found = append(found, t)
		}
	}
	if len(found) != 1 {
		return TcbInfo{}, failf("%s: expected one TcbInfo of type %s, found %d", label, kind, len(found))
	}
	return found[0], nil
}

// UEID returns the TCG UEID extension's type byte and the bytes after it.
func UEID(cert *x509.Certificate) (byte, []byte, bool) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidUEID) {
			continue
		}
		_, seq, _, err := tlv(ext.Value, 0)
		if err != nil {
			return 0, nil, false
		}
		_, raw, _, err := tlv(seq, 0)
		if err != nil || len(raw) == 0 {
			return 0, nil, false
		}
		return raw[0], raw[1:], true
	}
	return 0, nil, false
}

func loadCert(path string) (*x509.Certificate, error) {
	der, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// spkiDigest is the sha256 of a public key's SubjectPublicKeyInfo DER.
func spkiDigest(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return sha256Bytes(der), nil
}

// signedBy reports whether cert carries a valid signature from pub.
func signedBy(cert *x509.Certificate, pub *ecdsa.PublicKey) bool {
	issuer := &x509.Certificate{PublicKey: pub, PublicKeyAlgorithm: x509.ECDSA}
	return issuer.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

func sameName(a, b []byte) bool {
	var ra, rb pkix.RDNSequence
	if _, err := asn1.Unmarshal(a, &ra); err != nil {
		return false
	}
	if _, err := asn1.Unmarshal(b, &rb); err != nil {
		return false
	}
	return ra.String() == rb.String()
}

// checkSignedBy checks that cert names parent as its issuer and carries a valid signature from its key.
func checkSignedBy(cert, parent *x509.Certificate, label string) error {
	if !sameName(cert.RawIssuer, parent.RawSubject) {
		return failf("%s: issuer %s is not the expected parent", label, cert.Issuer.String())
	}
	pub, ok := parent.PublicKey.(*ecdsa.PublicKey)
	if !ok || !signedBy(cert, pub) {
		return failf("%s: signature does not verify under the parent key", label)
	}
	return nil
}
