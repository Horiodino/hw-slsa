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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/csv"
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
	"strconv"
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
	sig, err := s.priv.Sign(rand.Reader, d[:], crypto.SHA256)
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

// RoTFWModule is the module path the RoT firmware is built as.
const RoTFWModule = "example.com/exr01/rot-fw"

// RoTFirmware builds the RoT's runtime firmware from src with the Go
// toolchain, has the code signer sign it for the ROM, and signs its SLSA
// provenance, SBOM and CoRIM with the firmware platform's key. The build
// runs in a fresh directory holding only the sources and a go.mod, so it
// gives the same image wherever it runs; with isolate it runs in the
// sandbox, with no network (SLSA Build L3).
func RoTFirmware(bundle, src, key, codeSigner string, svn int64, isolate bool) error {
	started := Now()
	art, err := filepath.Abs(filepath.Join(bundle, "artifacts"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(art, 0o755); err != nil {
		return err
	}
	goroot, goDep, err := goToolchain()
	if err != nil {
		return err
	}
	goVersion := S(goDep, "annotations", "version")
	work, err := os.MkdirTemp("", "hslsa-rot-fw-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	files, err := filepath.Glob(filepath.Join(src, "*.go"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	var deps []Obj
	for _, f := range files {
		if err := copyFile(f, filepath.Join(work, filepath.Base(f))); err != nil {
			return err
		}
		d, err := sha256File(f)
		if err != nil {
			return err
		}
		deps = append(deps, rd(filepath.ToSlash(filepath.Join(filepath.Base(filepath.Dir(f)), filepath.Base(f))), d))
	}
	gomod := "module " + RoTFWModule + "\n\ngo 1.25\n"
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte(gomod), 0o644); err != nil {
		return err
	}
	deps = append(deps, rd("go.mod", sha256Bytes([]byte(gomod))))
	var sb *Sandbox
	out := filepath.Join(work, RoTFWImage)
	if isolate {
		if sb, err = NewSandbox(); err != nil {
			return err
		}
		sb.ReadOnly = []string{goroot}
		out = SandboxWork + "/" + RoTFWImage
	}
	ldflags := "-s -w -buildid="
	env := []string{"CGO_ENABLED=0", "GOFLAGS=-mod=mod", "GOPROXY=off", "GOTOOLCHAIN=local", "GOTELEMETRY=off",
		"GOCACHE=" + filepath.Join(work, ".cache"), "GOPATH=" + filepath.Join(work, ".gopath")}
	if isolate {
		env = []string{"CGO_ENABLED=0", "GOFLAGS=-mod=mod", "GOPROXY=off", "GOTOOLCHAIN=local", "GOTELEMETRY=off",
			"GOCACHE=/tmp/go-cache", "GOPATH=/tmp/go"}
	}
	if _, err := fwBuild(sb, work, env, [][]string{{filepath.Join(goroot, "bin", "go"), "build", "-trimpath", "-buildvcs=false", "-ldflags=" + ldflags, "-o", out, "."}}); err != nil {
		return fmt.Errorf("rot firmware: %w", err)
	}
	image := filepath.Join(art, RoTFWImage)
	if err := copyFile(filepath.Join(work, RoTFWImage), image); err != nil {
		return err
	}
	if err := os.Chmod(image, 0o755); err != nil {
		return err
	}
	imageRD, err := imageRD(image)
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

	if gh := githubSourceDep(); gh != nil {
		deps = append(deps, gh)
	}
	deps = append(deps, goDep)
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
				"flags": []any{"-trimpath", "-buildvcs=false", "-ldflags=" + ldflags}, "module": RoTFWModule,
			},
			"internalParameters":   isolationParams(sb, Obj{"CGO_ENABLED": "0", "GOPROXY": "off", "GOTOOLCHAIN": "local"}),
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
	idevid, ueid, _, err := rotSecrets(devDir)
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

// rotSecrets is what the part's ROM derives its keys from. A part from a
// lot with die identities (Wafer L3) has the DICE engine dieid.go models,
// whose UDS was burned at wafer sort: its IDevID key and UEID are the die's,
// and its CDIs chain from the die's CDI. Any other part has the UDS its test
// station had the die generate into its fuses.
func rotSecrets(devDir string) (idevid *ecdsa.PrivateKey, ueid, cdi []byte, err error) {
	if die, err := loadDie(devDir); err == nil {
		key, err := die.idevid()
		return key, die.UEID(), die.cdi(), err
	}
	fuses, err := ReadObj(filepath.Join(devDir, "fuses.json"))
	if err != nil {
		return nil, nil, nil, err
	}
	uds, err := hex.DecodeString(S(fuses, "uds"))
	if err != nil || len(uds) == 0 {
		return nil, nil, nil, errors.New("rot: no UDS in the fuses")
	}
	if ueid, err = hex.DecodeString(S(fuses, "ueid")); err != nil {
		return nil, nil, nil, err
	}
	key, err := deriveKey(uds, "IDevID")
	return key, ueid, uds, err
}

// hasDie says whether the part in devDir has a die identity from wafer sort.
func hasDie(devDir string) bool {
	_, err := os.Stat(filepath.Join(devDir, dieFile))
	return err == nil
}

// RoTProvAtt is the RoT vendor's provisioning record for one unit.
func RoTProvAtt(unit string) string { return ProvAtt(unit) }

// The vendor's test station, ps-02, is a simulated gang programmer, the
// "Example XG-8". Like a real one it knows nothing about HSLSA: it runs a job
// file and writes its own export (job.ini, log.csv, readback/, identity/),
// and the provisioning adapter (provadapter.go) turns that export into the
// records. Its profile is e2e/fpga/rot/station/xg8-profile.json.

const (
	xg8Sockets = 8
	xg8Regions = "FLASH"
)

// RoTJob writes the station's job file for the shipped lot, with the images it loads.
func RoTJob(bundle, scenarioPath, export string) error {
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	art := filepath.Join(bundle, "artifacts")
	if err := os.RemoveAll(export); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(export, "images"), 0o755); err != nil {
		return err
	}
	lotID := S(sc, "finalTest", "lotId")
	var b strings.Builder
	fmt.Fprintf(&b, "; Example XG-8 job file\n[job]\nid = FT-%s\nproduct = %s %s\nlot = %s\nsockets = %d\n",
		lotID, S(sc, "product", "partNumber"), S(sc, "product", "revision"), lotID, xg8Sockets)
	for i, f := range []string{RoTFWImage, RoTFWSig} {
		if err := copyFile(filepath.Join(art, f), filepath.Join(export, "images", f)); err != nil {
			return err
		}
		d, err := sha256File(filepath.Join(export, "images", f))
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "\n[image %d]\nfile = images/%s\nregion = %s%d\nchecksum = SHA256:%s\n", i+1, f, xg8Regions, i, strings.ToUpper(d))
	}
	if err := os.WriteFile(filepath.Join(export, "job.ini"), []byte(b.String()), 0o644); err != nil {
		return err
	}
	fmt.Printf("station job: FT-%s loads %s and %s\n", lotID, RoTFWImage, RoTFWSig)
	return nil
}

// xg8Log is the station's log as it writes it.
type xg8Log struct {
	w    *csv.Writer
	last time.Time
}

func (l *xg8Log) row(socket int, unit, op, target, value string, ok bool) error {
	t := time.Now().UTC().Truncate(time.Second)
	if t.Before(l.last) {
		t = l.last
	}
	l.last = t
	result := "PASS"
	if !ok {
		result = "FAIL"
	}
	return l.w.Write([]string{t.Format(time.RFC3339), strconv.Itoa(socket), unit, op, target, value, result})
}

func xg8Value(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "1"
		}
		return "0"
	case string:
		return x
	}
	return num(v)
}

// RoTStation runs the job on every shipped unit: it generates the UDS on the
// die, burns the public fuses, writes the images, reads everything back,
// exports the IDevID CSR from the part's ROM and stores the certificate the
// vendor's identity CA returns. devices gets each unit's state; export gets
// what the station writes.
func RoTStation(bundle, devices, keysDir, export string) error {
	art := filepath.Join(bundle, "artifacts")
	jobData, err := os.ReadFile(filepath.Join(export, "job.ini"))
	if err != nil {
		return err
	}
	job, err := parseINI(jobData)
	if err != nil {
		return err
	}
	shipped, err := ReadUnits(filepath.Join(art, "shipped-lot.txt"))
	if err != nil {
		return err
	}
	genealogy, err := ReadObj(filepath.Join(art, "genealogy.json"))
	if err != nil {
		return err
	}
	vendorHash, err := keyHash(filepath.Join(keysDir, "code-signer.pub.pem"))
	if err != nil {
		return err
	}
	for _, d := range []string{"readback", "identity"} {
		if err := os.MkdirAll(filepath.Join(export, d), 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(filepath.Join(export, "log.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	log := &xg8Log{w: csv.NewWriter(f)}
	if err := log.w.Write([]string{"timestamp", "socket", "serial", "operation", "target", "value", "result"}); err != nil {
		return err
	}

	var ca *rotCA
	for i, unit := range shipped {
		socket := i%xg8Sockets + 1
		// A unit named by its certificate (a lot with die identities) is in
		// the directory of its marked serial, where packaging put it.
		dev := filepath.Join(devices, unit)
		if serial := S(genealogy, "units", unit, "serial"); serial != "" {
			dev = filepath.Join(devices, serial)
		}
		die := hasDie(dev)
		if err := os.MkdirAll(filepath.Join(dev, "flash"), 0o755); err != nil {
			return err
		}
		if err := log.row(socket, unit, "BEGIN", "", job.values["job"]["id"], true); err != nil {
			return err
		}
		ueid := rotUEID(unit)
		if die {
			// The die has had its UDS since wafer sort; the station reads its UEID.
			_, id, _, err := rotSecrets(dev)
			if err != nil {
				return err
			}
			ueid = id
			if err := WriteJSON(filepath.Join(dev, "fuses.json"), Obj{"serial": unit}); err != nil {
				return err
			}
		} else {
			// The die's TRNG fills the UDS fuses; the station never sees the value.
			uds, err := randomHex(32)
			if err != nil {
				return err
			}
			if err := WriteJSON(filepath.Join(dev, "fuses.json"), Obj{"serial": unit, "uds": uds}); err != nil {
				return err
			}
			if err := log.row(socket, unit, "KEY_GEN", "uds", "uds:"+unit, true); err != nil {
				return err
			}
		}
		public := Obj{
			"ueid":            hex.EncodeToString(ueid),
			"vendor_key_hash": vendorHash,
			"lifecycle":       "production",
			"debug_locked":    true,
			"min_svn":         0,
		}
		fuses, err := ReadObj(filepath.Join(dev, "fuses.json"))
		if err != nil {
			return err
		}
		for _, k := range sortedKeys(public) {
			fuses[k] = public[k]
			if err := log.row(socket, unit, "FUSE_WRITE", k, xg8Value(public[k]), true); err != nil {
				return err
			}
		}
		if err := WriteJSON(filepath.Join(dev, "fuses.json"), fuses); err != nil {
			return err
		}
		for _, sec := range job.sections {
			if !strings.HasPrefix(sec, "image ") {
				continue
			}
			img := job.values[sec]
			data, err := os.ReadFile(filepath.Join(export, filepath.FromSlash(img["file"])))
			if err != nil {
				return err
			}
			name := filepath.Base(img["file"])
			if err := os.WriteFile(filepath.Join(dev, "flash", name), data, 0o644); err != nil {
				return err
			}
			if err := log.row(socket, unit, "PROGRAM", img["region"], img["file"], true); err != nil {
				return err
			}
			back, err := os.ReadFile(filepath.Join(dev, "flash", name))
			if err != nil {
				return err
			}
			dump := "readback/" + unit + "/" + img["region"] + ".bin"
			if err := os.MkdirAll(filepath.Join(export, "readback", unit), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(export, filepath.FromSlash(dump)), back, 0o644); err != nil {
				return err
			}
			want := strings.TrimPrefix(img["checksum"], "SHA256:")
			if err := log.row(socket, unit, "VERIFY", img["region"], dump, strings.EqualFold(sha256Bytes(back), want)); err != nil {
				return err
			}
		}
		burned, err := ReadObj(filepath.Join(dev, "fuses.json"))
		if err != nil {
			return err
		}
		for _, k := range sortedKeys(public) {
			if err := log.row(socket, unit, "FUSE_READ", k, xg8Value(burned[k]), true); err != nil {
				return err
			}
		}
		// The part's ROM derives its IDevID key from the UDS and answers with a
		// CSR; the vendor's identity CA endorses it and the station stores the
		// certificate. A die with an identity from sort already holds its
		// certificate, which the station reads from the part.
		csrDER, err := RoTCSR(dev)
		if err != nil {
			return err
		}
		var certDER []byte
		if die {
			d, err := loadDie(dev)
			if err != nil {
				return err
			}
			certDER = d.Cert
		} else {
			if ca == nil {
				if ca, err = loadRoTCA(keysDir); err != nil {
					return err
				}
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				return err
			}
			if certDER, err = Endorse(csr, ca.key, ca.name); err != nil {
				return err
			}
		}
		csrFile, certFile := "identity/"+unit+".csr.der", "identity/"+unit+".crt.der"
		if err := os.WriteFile(filepath.Join(export, csrFile), csrDER, 0o644); err != nil {
			return err
		}
		if err := log.row(socket, unit, "CSR_EXPORT", "IDEVID", csrFile, true); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(export, certFile), certDER, 0o644); err != nil {
			return err
		}
		if err := log.row(socket, unit, "CERT_IMPORT", "IDEVID", certFile, true); err != nil {
			return err
		}
		if err := log.row(socket, unit, "END", "", "", true); err != nil {
			return err
		}
	}
	log.w.Flush()
	if err := log.w.Error(); err != nil {
		return err
	}
	fmt.Printf("station ps-02: %d units programmed, export in %s\n", len(shipped), export)
	return nil
}

// rotCA is the vendor's identity CA at the test station, for parts without a die identity.
type rotCA struct {
	key  *ecdsa.PrivateKey
	name string
}

func loadRoTCA(keysDir string) (*rotCA, error) {
	key, err := loadECKey(filepath.Join(keysDir, "identity-ca.key.pem"))
	if err != nil {
		return nil, err
	}
	name, err := os.ReadFile(filepath.Join(keysDir, "identity-ca.name.txt"))
	if err != nil {
		return nil, err
	}
	return &rotCA{key: key, name: strings.TrimSpace(string(name))}, nil
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
	idevid, ueid, cdi, err := rotSecrets(devDir)
	if err != nil {
		return held("no device secret: %v", err)
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

	// DICE: the alias key comes from a CDI over the firmware's measurement.
	mac := hmac.New(sha256.New, cdi)
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
