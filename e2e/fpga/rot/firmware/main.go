// Command rot-fw is the runtime firmware of the simulated board root of trust
// in the FPGA board example (docs/fpga-board-example.md).
//
// The RoT's mask ROM (modeled by hslsa) verifies this image's signature
// against the vendor key hash in the RoT's fuses, measures it, derives the
// RoT's DICE alias key and runs it. This firmware then does the RoT's job on
// the board: while it holds the FPGA in reset (CRESET_B low), it reads the
// boot manifest from the board's SPI flash, checks that the manifest is signed
// by the key whose hash the board owner burned into the RoT, checks every
// image the manifest lists against its digest, and only then releases the
// FPGA. It reports what it verified in a DICE certificate signed with the
// alias key: one TcbInfo per image, so a verifier can check the measurements
// against the board's reference values.
//
// It uses only the Go standard library, so its provenance and SBOM name the
// Go toolchain and nothing else. On a real board the same logic would run on
// the RoT's own processor; here the device model runs it as a host program.
//
//	rot-fw --flash flash.bin --otp fuses.json --alias-cert alias.der --out dir < alias.key.pem
//
// Exit status 0 means the FPGA was released; 3 means it was held in reset.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	model        = "EXR-01"
	imageLayer   = 2
	sha256OID    = "2.16.840.1.101.3.4.2.1"
	manifestFmt  = "hslsa-boot-manifest/v1"
	exitHeld     = 3
	manifestSlot = 4096
)

var (
	oidMultiTcbInfo = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 5}
	oidUEID         = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 4}
)

// signedManifest is the boot manifest as it sits in flash: the signed payload
// and the signer's public key, whose SPKI digest must equal the owner fuse.
type signedManifest struct {
	Payload   string `json:"payload"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

type image struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
}

type manifest struct {
	Format  string  `json:"format"`
	Vendor  string  `json:"vendor"`
	Product string  `json:"product"`
	SVN     int64   `json:"svn"`
	Images  []image `json:"images"`
}

type otp struct {
	OwnerKeyHash   string `json:"owner_key_hash"`
	ManifestOffset int64  `json:"manifest_offset"`
	MinSVN         int64  `json:"owner_min_svn"`
	UEID           string `json:"ueid"`
}

func main() {
	flashPath := flag.String("flash", "", "the board's SPI flash contents")
	otpPath := flag.String("otp", "", "the RoT's fuses")
	aliasCert := flag.String("alias-cert", "", "the alias certificate the ROM issued for this firmware")
	out := flag.String("out", "", "directory for platform.der")
	flag.Parse()
	log := func(format string, a ...any) { fmt.Printf("rot-fw: "+format+"\n", a...) }
	measured, err := verify(*flashPath, *otpPath)
	if err != nil {
		log("holding the FPGA in reset: %v", err)
		os.Exit(exitHeld)
	}
	if err := report(measured, *otpPath, *aliasCert, *out); err != nil {
		log("holding the FPGA in reset: %v", err)
		os.Exit(exitHeld)
	}
	for _, m := range measured.Images {
		log("verified %s (%s) sha256:%s", m.Name, m.Role, m.SHA256)
	}
	log("released CRESET_B: the FPGA configures from flash")
}

func readOTP(path string) (otp, error) {
	var o otp
	data, err := os.ReadFile(path)
	if err != nil {
		return o, err
	}
	err = json.Unmarshal(data, &o)
	return o, err
}

// verify checks the manifest and every image it lists. Nothing is released
// unless all of it holds.
func verify(flashPath, otpPath string) (*manifest, error) {
	fuses, err := readOTP(otpPath)
	if err != nil {
		return nil, fmt.Errorf("fuses: %v", err)
	}
	if fuses.OwnerKeyHash == "" {
		return nil, errors.New("no owner key hash in the fuses: the board was never provisioned")
	}
	flash, err := os.ReadFile(flashPath)
	if err != nil {
		return nil, fmt.Errorf("flash: %v", err)
	}
	off := fuses.ManifestOffset
	if off < 0 || off+4 > int64(len(flash)) {
		return nil, errors.New("no boot manifest in flash")
	}
	n := int64(binary.BigEndian.Uint32(flash[off : off+4]))
	if n == 0 || n > manifestSlot-4 || off+4+n > int64(len(flash)) {
		return nil, errors.New("no boot manifest in flash")
	}
	var sm signedManifest
	if err := json.Unmarshal(flash[off+4:off+4+n], &sm); err != nil {
		return nil, fmt.Errorf("boot manifest: %v", err)
	}
	block, _ := pem.Decode([]byte(sm.PublicKey))
	if block == nil {
		return nil, errors.New("boot manifest: no public key")
	}
	spki := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(spki[:]) != fuses.OwnerKeyHash {
		return nil, errors.New("boot manifest is signed by a key other than the owner key in the fuses")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("boot manifest key: %v", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("boot manifest key is not ECDSA")
	}
	payload, err := base64.StdEncoding.DecodeString(sm.Payload)
	if err != nil {
		return nil, fmt.Errorf("boot manifest payload: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sm.Signature)
	if err != nil {
		return nil, fmt.Errorf("boot manifest signature: %v", err)
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(ec, digest[:], sig) {
		return nil, errors.New("boot manifest signature does not verify")
	}
	var m manifest
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("boot manifest payload: %v", err)
	}
	if m.Format != manifestFmt {
		return nil, fmt.Errorf("boot manifest format %q", m.Format)
	}
	if m.SVN < fuses.MinSVN {
		return nil, fmt.Errorf("boot manifest SVN %d is below the anti-rollback fuse %d", m.SVN, fuses.MinSVN)
	}
	if len(m.Images) == 0 {
		return nil, errors.New("boot manifest lists no images")
	}
	for _, img := range m.Images {
		if img.Offset < 0 || img.Length <= 0 || img.Offset+img.Length > int64(len(flash)) {
			return nil, fmt.Errorf("%s lies outside the flash", img.Name)
		}
		got := sha256.Sum256(flash[img.Offset : img.Offset+img.Length])
		if hex.EncodeToString(got[:]) != img.SHA256 {
			return nil, fmt.Errorf("%s in flash does not match the manifest (sha256:%x)", img.Name, got)
		}
	}
	return &m, nil
}

// report issues the platform certificate: the alias key's statement of
// which images this RoT verified and released, one TcbInfo per image.
func report(m *manifest, otpPath, aliasCertPath, out string) error {
	fuses, err := readOTP(otpPath)
	if err != nil {
		return err
	}
	keyPEM, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return errors.New("no alias key from the ROM")
	}
	alias, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("alias key: %v", err)
	}
	der, err := os.ReadFile(aliasCertPath)
	if err != nil {
		return err
	}
	parent, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("alias certificate: %v", err)
	}
	var infos [][]byte
	for i, img := range m.Images {
		info, err := tcbInfo(m.Vendor, m.Product, img.Role, m.SVN, imageLayer, int64(i+1), img.SHA256)
		if err != nil {
			return err
		}
		infos = append(infos, info)
	}
	multi := seq(infos...)
	ueid, err := hex.DecodeString(fuses.UEID)
	if err != nil {
		return fmt.Errorf("ueid fuse: %v", err)
	}
	ueidExt, err := asn1.Marshal(struct{ UEID []byte }{ueid})
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(1)),
		Subject:      pkix.Name{CommonName: model + " platform measurements " + hex.EncodeToString(ueid)},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: oidUEID, Value: ueidExt},
			{Id: oidMultiTcbInfo, Value: multi},
		},
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &alias.PublicKey, alias)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "platform.der"), cert, 0o644)
}

// DER, by hand, so that fields such as index 0 are never dropped.

func tlv(tag byte, content []byte) []byte {
	n := len(content)
	var hdr []byte
	switch {
	case n < 0x80:
		hdr = []byte{tag, byte(n)}
	case n < 0x100:
		hdr = []byte{tag, 0x81, byte(n)}
	default:
		hdr = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	}
	return append(hdr, content...)
}

func seq(items ...[]byte) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, it...)
	}
	return tlv(0x30, body)
}

func intContent(v int64) []byte {
	der, _ := asn1.Marshal(v)
	return der[2:]
}

// tcbInfo is a TCG DiceTcbInfo: vendor [0], model [1], svn [3], layer [4],
// index [5], fwids [6] and type [9]. Vendor and model are the board's, from
// the manifest, since the images are the board owner's.
func tcbInfo(vendor, product, role string, svn, layer, index int64, sha256Hex string) ([]byte, error) {
	digest, err := hex.DecodeString(sha256Hex)
	if err != nil {
		return nil, err
	}
	oid, err := asn1.Marshal(parseOID(sha256OID))
	if err != nil {
		return nil, err
	}
	fwid := seq(oid, tlv(0x04, digest))
	return seq(
		tlv(0x80, []byte(vendor)),
		tlv(0x81, []byte(product)),
		tlv(0x83, intContent(svn)),
		tlv(0x84, intContent(layer)),
		tlv(0x85, intContent(index)),
		tlv(0xa6, fwid),
		tlv(0x89, []byte(role)),
	), nil
}

func parseOID(s string) asn1.ObjectIdentifier {
	var oid asn1.ObjectIdentifier
	n := 0
	for _, c := range s + "." {
		if c == '.' {
			oid = append(oid, n)
			n = 0
			continue
		}
		n = n*10 + int(c-'0')
	}
	return oid
}
