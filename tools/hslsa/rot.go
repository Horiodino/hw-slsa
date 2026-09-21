package hslsa

// Board root of trust for the FPGA board example (e2e/fpga).
//
// The example's board has an iCE40 FPGA, which has no secure-boot ROM, so it
// reaches Firmware L2 only through the spec's board-level root of trust rule:
// a root of trust on the board verifies every image in the board's flash
// before it lets the FPGA out of reset, and that root of trust is itself
// attested. The root of trust here is a simulated part, EXR-01 from "Example
// RoT Co". Its vendor's chain is the PicoRV32 chip chain (its CPU core) plus
// what makes it a root of trust:
//
//	firmware   its runtime firmware (e2e/fpga/rot/firmware), built with Go,
//	           with SLSA provenance, an SBOM, a vendor signature that its ROM
//	           checks, and a CoRIM with the firmware's reference value
//	provision  per unit at final test: a unique device secret (UDS) in fuses,
//	           the vendor key hash, the firmware in its internal flash, and an
//	           IDevID certificate endorsed by the vendor's identity CA
//	hbom       the chip HBOM with firmware[] and a DICE identity
//
// The part itself is modeled here: RoTCSR is what its ROM answers when the
// test station asks for the IDevID CSR, and RoTBoot is its mask ROM at power
// on. The ROM checks the firmware's signature against the vendor key hash,
// measures it, derives the DICE alias key, issues the alias certificate and
// runs the firmware, which does the board work (rot-fw/main.go).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	RoTVendor      = "Example RoT Co"
	RoTModel       = "EXR-01"
	RoTFWImage     = "rot-fw"
	RoTFWSig       = "rot-fw.sig.json"
	RoTFWAtt       = "fw-rot.intoto.json"
	RoTCoRIMFile   = "rot-fw.corim"
	RoTSBOM        = "sbom-rot-fw.cdx.json"
	RoTFWTcbType   = "rot-fw"
	GoBuildType    = NS + "/firmware/go-build@v1"
	RoTImageFormat = "hslsa-rot-image/v1"
	// SHA256OID is the FWID hash algorithm of the board's measurements.
	SHA256OID = "2.16.840.1.101.3.4.2.1"
	// rotHeld is the firmware's exit status when it keeps the FPGA in reset.
	rotHeld = 3
)

// Signed blobs: a payload, the signer's public key and an ECDSA signature
// over the payload's sha256. The RoT's ROM reads its firmware's signature in
// this form, and its firmware reads the board's boot manifest in it.

func signBlob(payload []byte, s *Signer) (Obj, error) {
	d := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, d[:])
	if err != nil {
		return nil, err
	}
	return Obj{
		"payload":   base64.StdEncoding.EncodeToString(payload),
		"publicKey": s.Key.PEM,
		"signature": base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// openBlob verifies a signed blob and returns its payload and the sha256 of its signer's SPKI.
func openBlob(b Obj) ([]byte, string, error) {
	block, _ := pem.Decode([]byte(S(b, "publicKey")))
	if block == nil {
		return nil, "", errors.New("no public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", errors.New("not an ECDSA key")
	}
	payload, err := base64.StdEncoding.DecodeString(S(b, "payload"))
	if err != nil {
		return nil, "", err
	}
	sig, err := base64.StdEncoding.DecodeString(S(b, "signature"))
	if err != nil {
		return nil, "", err
	}
	d := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(ec, d[:], sig) {
		return nil, "", errors.New("signature does not verify")
	}
	return payload, sha256Bytes(block.Bytes), nil
}

// keyHash is the sha256 of a PEM public key's SPKI, the value a key-hash fuse holds.
func keyHash(pemPath string) (string, error) {
	data, err := os.ReadFile(pemPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("%s: no PEM block", pemPath)
	}
	return sha256Bytes(block.Bytes), nil
}

// DER, by hand, for the DICE extensions.

func derTLV(tag byte, content []byte) []byte {
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

func derSeq(items ...[]byte) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, it...)
	}
	return derTLV(0x30, body)
}

func derIntContent(v int64) []byte {
	der, _ := asn1.Marshal(v)
	return der[2:]
}

// tcbInfoDER encodes a TCG DiceTcbInfo with vendor, model, svn, layer, index
// (left out when negative), one sha256 FWID and type.
func tcbInfoDER(vendor, model, kind string, svn, layer, index int64, sha256Hex string) ([]byte, error) {
	digest, err := hex.DecodeString(sha256Hex)
	if err != nil {
		return nil, err
	}
	oid, err := asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	if err != nil {
		return nil, err
	}
	fields := [][]byte{
		derTLV(0x80, []byte(vendor)),
		derTLV(0x81, []byte(model)),
		derTLV(0x83, derIntContent(svn)),
		derTLV(0x84, derIntContent(layer)),
	}
	if index >= 0 {
		fields = append(fields, derTLV(0x85, derIntContent(index)))
	}
	fields = append(fields, derTLV(0xa6, derSeq(oid, derTLV(0x04, digest))), derTLV(0x89, []byte(kind)))
	return derSeq(fields...), nil
}

func ueidExtension(ueid []byte) (pkix.Extension, error) {
	v, err := asn1.Marshal(struct{ UEID []byte }{ueid})
	return pkix.Extension{Id: oidUEID, Value: v}, err
}

// deriveKey turns a secret into a P-256 key, the same key every time: a
// stand-in for the DICE key derivation in the RoT's ROM.
func deriveKey(secret []byte, label string) (*ecdsa.PrivateKey, error) {
	n := elliptic.P256().Params().N
	for ctr := 0; ctr < 256; ctr++ {
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(label))
		m.Write([]byte{byte(ctr)})
		d := m.Sum(nil)
		if k := new(big.Int).SetBytes(d); k.Sign() > 0 && k.Cmp(n) < 0 {
			return ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
		}
	}
	return nil, errors.New("key derivation failed")
}

// rotUEID is the unit's UEID: type 1 (random) followed by its serial, padded to 16 bytes.
func rotUEID(unit string) []byte {
	ueid := make([]byte, max(16, len(unit)))
	copy(ueid, unit)
	return append([]byte{1}, ueid...)
}

func rotName(kind string, ueid []byte) ([]byte, error) {
	return utf8Name(fmt.Sprintf("%s %s %s", RoTModel, kind, hex.EncodeToString(ueid)))
}

// RoT vendor: firmware

// RoTFirmware builds the RoT's runtime firmware from src with the Go
// toolchain, has the code signer sign it for the ROM, and signs its SLSA
// provenance, SBOM and CoRIM with the firmware platform's key.
func RoTFirmware(bundle, src, key, codeSigner string, svn int64) error {
	started := Now()
	art, err := filepath.Abs(filepath.Join(bundle, "artifacts"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(art, 0o755); err != nil {
		return err
	}
	image := filepath.Join(art, RoTFWImage)
	ldflags := "-s -w -buildid="
	env := append(os.Environ(), "CGO_ENABLED=0")
	proc, err := runCmd(src, env, "go", "build", "-trimpath", "-buildvcs=false", "-ldflags="+ldflags, "-o", image, ".")
	if err != nil {
		return err
	}
	if proc.Code != 0 {
		return fmt.Errorf("rot firmware: go build failed: %s", proc.Stderr)
	}
	goTool, err := tool("go", "version")
	if err != nil {
		return err
	}
	goVersion := strings.TrimPrefix(strings.Fields(S(goTool, "version") + " x x")[2], "go")
	imageRD, err := fileRD(image, "")
	if err != nil {
		return err
	}
	digest := S(imageRD, "digest", "sha256")

	// The code signer signs the image for the ROM's secure boot.
	cs, err := LoadSigner(codeSigner)
	if err != nil {
		return err
	}
	payload := compactJSON(Obj{"format": RoTImageFormat, "image": RoTFWImage, "sha256": digest, "svn": svn})
	blob, err := signBlob(payload, cs)
	if err != nil {
		return err
	}
	if err := WriteJSON(filepath.Join(art, RoTFWSig), blob); err != nil {
		return err
	}
	sigRD, err := fileRD(filepath.Join(art, RoTFWSig), "")
	if err != nil {
		return err
	}

	sbom := Obj{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"metadata": Obj{
			"component": Obj{
				"type": "firmware", "bom-ref": RoTFWImage, "name": RoTFWImage,
				"supplier": Obj{"name": RoTVendor},
				"hashes":   []Obj{{"alg": "SHA-256", "content": digest}},
			},
			"tools": Obj{"components": []Obj{{"type": "application", "name": "hslsa", "version": "0.1"}}},
		},
		"components": []Obj{{
			"type": "library", "bom-ref": "pkg:golang/stdlib@" + goVersion, "name": "stdlib",
			"version": goVersion, "purl": "pkg:golang/stdlib@" + goVersion,
		}},
	}
	if err := WriteJSON(filepath.Join(art, RoTSBOM), sbom); err != nil {
		return err
	}
	sbomRD, err := fileRD(filepath.Join(art, RoTSBOM), "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	s := uint64(svn)
	layer := uint64(1)
	refs := []RefValue{{Env: DiceEnv{Type: RoTFWTcbType, Vendor: RoTVendor, Model: RoTModel, Layer: &layer}, Digests: []FWID{{SHA256OID, digest}}, SVN: &s}}
	if err := WriteCoRIM(filepath.Join(art, RoTCoRIMFile), RoTFWImage+"@sha256:"+digest, RoTVendor+" firmware build platform",
		"firmware-platform", refs, signer); err != nil {
		return err
	}
	corimRD, err := fileRD(filepath.Join(art, RoTCoRIMFile), "")
	if err != nil {
		return err
	}

	var deps []Obj
	files, err := filepath.Glob(filepath.Join(src, "*.go"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		d, err := sha256File(f)
		if err != nil {
			return err
		}
		deps = append(deps, rd(filepath.ToSlash(filepath.Join(filepath.Base(filepath.Dir(f)), filepath.Base(f))), d))
	}
	if gh := githubSourceDep(); gh != nil {
		deps = append(deps, gh)
	}
	deps = append(deps, Obj{"name": "go", "uri": "pkg:golang/go@" + goVersion, "digest": get(goTool, "digest")})
	run := builder()
	O(run, "metadata")["startedOn"] = started
	O(run, "metadata")["finishedOn"] = Now()
	run["byproducts"] = []Obj{sbomRD, corimRD}
	pred := Obj{
		"buildDefinition": Obj{
			"buildType": GoBuildType,
			"externalParameters": Obj{
				"target": RoTFWImage, "package": ".", "svn": svn,
				"goos": runtime.GOOS, "goarch": runtime.GOARCH,
				"flags": []any{"-trimpath", "-buildvcs=false", "-ldflags=" + ldflags},
			},
			"internalParameters":   Obj{"CGO_ENABLED": "0"},
			"resolvedDependencies": deps,
		},
		"runDetails": run,
	}
	stmt, err := statement([]Obj{imageRD, sigRD}, SLSAProvenance, pred)
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", RoTFWAtt)); err != nil {
		return err
	}
	fmt.Printf("rot firmware: %s sha256:%s, signed for secure boot, svn %d\n", RoTFWImage, digest[:16], svn)
	return nil
}

// RoT vendor: per-unit provisioning at final test

// RoTCSR is the part's ROM answering the test station: a CSR for its IDevID
// key, which it derives from the UDS in its fuses and never exports.
func RoTCSR(devDir string) ([]byte, error) {
	fuses, err := ReadObj(filepath.Join(devDir, "fuses.json"))
	if err != nil {
		return nil, err
	}
	uds, err := hex.DecodeString(S(fuses, "uds"))
	if err != nil || len(uds) == 0 {
		return nil, errors.New("rot: no UDS in the fuses")
	}
	ueid, err := hex.DecodeString(S(fuses, "ueid"))
	if err != nil {
		return nil, err
	}
	idevid, err := deriveKey(uds, "IDevID")
	if err != nil {
		return nil, err
	}
	name, err := rotName("IDevID", ueid)
	if err != nil {
		return nil, err
	}
	ext, err := ueidExtension(ueid)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject: name, ExtraExtensions: []pkix.Extension{ext}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, idevid)
}

// RoTProvAtt is the RoT vendor's provisioning record for one unit.
func RoTProvAtt(unit string) string { return ProvAtt(unit) }

// RoTProvision programs every shipped unit at the final test station: fuses,
// firmware and an endorsed IDevID, then signs one record per unit.
func RoTProvision(bundle, devices, keysDir, scenarioPath string) error {
	art := filepath.Join(bundle, "artifacts")
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	station := O(sc, "provisioning")
	trust, err := LoadTrustRoot(filepath.Join(bundle, "trust-root.json"))
	if err != nil {
		return err
	}
	final, err := releasedSubject(bundle)
	if err != nil {
		return err
	}
	relEnv := envRD(bundle, AttName("release"))
	shipped, err := ReadUnits(filepath.Join(art, "shipped-lot.txt"))
	if err != nil {
		return err
	}
	lotID := S(sc, "finalTest", "lotId")
	caKey, err := loadECKey(filepath.Join(keysDir, "identity-ca.key.pem"))
	if err != nil {
		return err
	}
	caName, err := os.ReadFile(filepath.Join(keysDir, "identity-ca.name.txt"))
	if err != nil {
		return err
	}
	vendorHash, err := keyHash(filepath.Join(keysDir, "code-signer.pub.pem"))
	if err != nil {
		return err
	}
	signer, err := LoadSigner(filepath.Join(keysDir, S(station, "signer")+".key.pem"))
	if err != nil {
		return err
	}
	// The station checks the image's provenance before it writes the image anywhere.
	image := filepath.Join(art, RoTFWImage)
	imageRD, err := fileRD(image, "")
	if err != nil {
		return err
	}
	fwEnv := envRD(bundle, RoTFWAtt)
	prov, provErr := trust.Open(filepath.Join(bundle, "att", RoTFWAtt), "firmware-platform", SLSAProvenance)
	provOK := provErr == nil && sha256Set(Objs(prov, "subject"))[S(imageRD, "digest", "sha256")]

	for _, unit := range shipped {
		dev := filepath.Join(devices, unit)
		if err := os.MkdirAll(filepath.Join(dev, "flash"), 0o755); err != nil {
			return err
		}
		uds, err := randomHex(32)
		if err != nil {
			return err
		}
		ueid := rotUEID(unit)
		public := Obj{
			"ueid":            hex.EncodeToString(ueid),
			"vendor_key_hash": vendorHash,
			"lifecycle":       "production",
			"debug_locked":    true,
			"min_svn":         0,
		}
		fuses := Obj{"serial": unit, "uds": uds}
		for k, v := range public {
			fuses[k] = v
		}
		if err := WriteJSON(filepath.Join(dev, "fuses.json"), fuses); err != nil {
			return err
		}
		for _, f := range []string{RoTFWImage, RoTFWSig} {
			if err := copyFile(filepath.Join(art, f), filepath.Join(dev, "flash", f)); err != nil {
				return err
			}
		}
		csrDER, err := RoTCSR(dev)
		if err != nil {
			return err
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return err
		}
		certDER, err := Endorse(csr, caKey, strings.TrimSpace(string(caName)))
		if err != nil {
			return err
		}
		csrName, certName := "rot-"+unit+".csr.der", "rot-"+unit+".idevid.der"
		if err := os.WriteFile(filepath.Join(art, csrName), csrDER, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(art, certName), certDER, 0o644); err != nil {
			return err
		}
		idevidDigest, err := spkiDigest(csr.PublicKey)
		if err != nil {
			return err
		}

		// Read back what the unit now holds.
		readback, err := sha256File(filepath.Join(dev, "flash", RoTFWImage))
		if err != nil {
			return err
		}
		burned, err := ReadObj(filepath.Join(dev, "fuses.json"))
		if err != nil {
			return err
		}
		delete(burned, "uds")
		delete(burned, "serial")
		checks := []Obj{
			check("image-provenance-verified", provOK, errDetail(provErr, "fw-rot provenance signed by the firmware platform names this image")),
			check("image-readback", readback == S(imageRD, "digest", "sha256"), ""),
			check("fuse-readback", canonicalDigest(burned) == canonicalDigest(public), ""),
			check("csr-self-signature", csr.CheckSignature() == nil, ""),
			check("lifecycle-production", true, "production, debug locked"),
		}
		csrRD, err := fileRD(filepath.Join(art, csrName), csrName)
		if err != nil {
			return err
		}
		certRD, err := fileRD(filepath.Join(art, certName), certName)
		if err != nil {
			return err
		}
		pred := Obj{
			"buildDefinition": Obj{
				"buildType":            ProvisionType,
				"externalParameters":   Obj{"unit": unit, "lotId": lotID, "stage": "final-test"},
				"resolvedDependencies": []Obj{fwEnv, imageRD, csrRD, certRD},
			},
			"runDetails": Obj{
				"builder":  Obj{"id": "urn:hslsa:site:" + slug(S(station, "site", "name"))},
				"metadata": Obj{"invocationId": "provision:" + unit, "finishedOn": Now()},
			},
			"hwProvision": Obj{
				"station":   get(station, "id"),
				"site":      get(station, "site"),
				"unit":      "urn:hslsa:unit:" + unit,
				"lot":       "urn:hslsa:lot:" + lotID,
				"designRef": Obj{"name": final["name"], "digest": final["digest"], "release": relEnv},
				"images": []Obj{{
					"name": RoTFWImage, "role": "runtime", "storage": "on-die-flash",
					"digest": get(imageRD, "digest"), "readback": Obj{"sha256": readback}, "provenanceVerified": provOK,
				}},
				"fuses":   public,
				"secrets": []Obj{{"field": "uds", "keyId": "uds:" + unit, "origin": "generated-on-die"}},
				"identity": Obj{
					"scheme":          "DICE",
					"ueid":            hex.EncodeToString(ueid),
					"idevidPublicKey": Obj{"sha256": idevidDigest},
					"certificate":     certRD,
					"endorsingCa":     strings.TrimSpace(string(caName)),
				},
				"checks": checks,
			},
		}
		stmt, err := statement([]Obj{rd("urn:hslsa:unit:"+unit, idevidDigest)}, FWProvisioning, pred)
		if err != nil {
			return err
		}
		if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", RoTProvAtt(unit))); err != nil {
			return err
		}
		if failed := failedChecks(checks); len(failed) > 0 {
			return fmt.Errorf("provisioning %s: %s failed (recorded in the attestation)", unit, strings.Join(failed, ", "))
		}
	}
	fmt.Printf("rot provisioning: %d units programmed, each with an endorsed IDevID\n", len(shipped))
	return nil
}

// RoTHBOM signs the RoT's chip HBOM with its firmware listed.
func RoTHBOM(bundle, lockPath, scenarioPath, key string) error {
	fw := Obj{
		"name": RoTFWImage, "role": "runtime", "storage": "on-die-flash",
		"digest":             fileDigest(filepath.Join(bundle, "artifacts", RoTFWImage)),
		"sbomRef":            fileRef(bundle, "artifacts/"+RoTSBOM),
		"referenceValuesRef": fileRef(bundle, "artifacts/"+RoTCoRIMFile),
	}
	O(fw, "referenceValuesRef")["mediaType"] = CoRIMMediaType
	return BuildChipHBOM(bundle, lockPath, scenarioPath, key, nil, []Obj{fw})
}

// The part: its mask ROM at power on

// RoTBoot powers on one RoT unit on its board. The ROM verifies the RoT
// firmware against the vendor key hash in the fuses, measures it, issues the
// alias certificate and runs the firmware against the board's flash. It
// returns whether the FPGA was released; outDir gets alias.der, platform.der
// (only when released) and rot.log.
func RoTBoot(devDir, flashPath, outDir string) (bool, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return false, err
	}
	logPath := filepath.Join(outDir, "rot.log")
	held := func(format string, a ...any) (bool, error) {
		msg := fmt.Sprintf("rom: holding the FPGA in reset: "+format+"\n", a...)
		return false, os.WriteFile(logPath, []byte(msg), 0o644)
	}
	fuses, err := ReadObj(filepath.Join(devDir, "fuses.json"))
	if err != nil {
		return false, err
	}
	uds, err := hex.DecodeString(S(fuses, "uds"))
	if err != nil || len(uds) == 0 {
		return held("no UDS in the fuses")
	}
	ueid, err := hex.DecodeString(S(fuses, "ueid"))
	if err != nil {
		return held("unreadable UEID fuse")
	}
	image, err := os.ReadFile(filepath.Join(devDir, "flash", RoTFWImage))
	if err != nil {
		return held("no firmware in internal flash")
	}
	sig, err := ReadObj(filepath.Join(devDir, "flash", RoTFWSig))
	if err != nil {
		return held("no firmware signature in internal flash")
	}
	payload, signerHash, err := openBlob(sig)
	if err != nil {
		return held("firmware signature: %v", err)
	}
	if signerHash != S(fuses, "vendor_key_hash") {
		return held("firmware is signed by a key other than the vendor key in the fuses")
	}
	meta, err := decodeJSON(payload)
	if err != nil || S(meta, "format") != RoTImageFormat {
		return held("firmware signature payload is not a RoT image statement")
	}
	measurement := sha256Bytes(image)
	if S(meta, "sha256") != measurement {
		return held("firmware in internal flash is not the image its signature names")
	}
	svn, _ := Int(meta, "svn")
	minSVN, _ := Int(fuses, "min_svn")
	if svn < minSVN {
		return held("firmware SVN %d is below the anti-rollback fuse %d", svn, minSVN)
	}

	// DICE: the IDevID key comes from the UDS; the alias key from a CDI over the measurement.
	idevid, err := deriveKey(uds, "IDevID")
	if err != nil {
		return false, err
	}
	mac := hmac.New(sha256.New, uds)
	mac.Write([]byte("CDI"))
	mac.Write([]byte(measurement))
	alias, err := deriveKey(mac.Sum(nil), "alias")
	if err != nil {
		return false, err
	}
	issuer, err := rotName("IDevID", ueid)
	if err != nil {
		return false, err
	}
	subject, err := rotName("alias", ueid)
	if err != nil {
		return false, err
	}
	tcb, err := tcbInfoDER(RoTVendor, RoTModel, RoTFWTcbType, svn, 1, -1, measurement)
	if err != nil {
		return false, err
	}
	ueidExt, err := ueidExtension(ueid)
	if err != nil {
		return false, err
	}
	serial := new(big.Int).SetBytes([]byte(measurement[:16]))
	tmpl := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		RawSubject:            subject,
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions:       []pkix.Extension{ueidExt, {Id: oidTcbInfo, Value: tcb}},
	}
	parent := &x509.Certificate{RawSubject: issuer, PublicKey: &idevid.PublicKey}
	aliasDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &alias.PublicKey, idevid)
	if err != nil {
		return false, err
	}
	aliasPath := filepath.Join(outDir, "alias.der")
	if err := os.WriteFile(aliasPath, aliasDER, 0o644); err != nil {
		return false, err
	}

	// Run the firmware with the alias key. It holds the FPGA in reset unless every image verifies.
	tmp, err := os.MkdirTemp("", "hslsa-rot-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	bin := filepath.Join(tmp, RoTFWImage)
	if err := os.WriteFile(bin, image, 0o755); err != nil {
		return false, err
	}
	otp := filepath.Join(tmp, "otp.json")
	if err := WriteJSON(otp, fuses); err != nil {
		return false, err
	}
	keyDER, err := x509.MarshalECPrivateKey(alias)
	if err != nil {
		return false, err
	}
	absFlash, err := filepath.Abs(flashPath)
	if err != nil {
		return false, err
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return false, err
	}
	cmd := exec.Command(bin, "--flash", absFlash, "--otp", otp, "--alias-cert", filepath.Join(absOut, "alias.der"), "--out", absOut)
	cmd.Stdin = strings.NewReader(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	out, runErr := cmd.CombinedOutput()
	log := fmt.Sprintf("rom: firmware verified, sha256:%s svn %d, alias certificate issued\n%s", measurement, svn, out)
	if err := os.WriteFile(logPath, []byte(log), 0o644); err != nil {
		return false, err
	}
	var ee *exec.ExitError
	switch {
	case runErr == nil:
		return true, nil
	case errors.As(runErr, &ee) && ee.ExitCode() == rotHeld:
		return false, nil
	}
	return false, fmt.Errorf("rot firmware: %v: %s", runErr, out)
}
