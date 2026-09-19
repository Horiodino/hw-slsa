package hslsa

// Tamper tests for the Caliptra example: every broken link from RTL to a booted device must fail, for the right reason.
//
// Needs the output of `e2e/caliptra/run.sh produce` and `verify`
// (HSLSA_CALIPTRA_OUT, default out/caliptra): the bundle, and the certificates
// the booted units returned. As in e2e_test.go, the producer keys never leave
// the produce job, so the fixture re-signs every record with fresh test keys,
// and endorses the units' IDevID CSRs with a fresh identity CA. Tests can then
// forge validly signed lies.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	calDir      = filepath.Join(root, "e2e", "caliptra")
	calLock     = filepath.Join(calDir, "caliptra.lock.json")
	calScenario = filepath.Join(calDir, "mfg-scenario.json")
	calPolicy   = filepath.Join(calDir, "policy.json")
	calRoles    = []string{"flow-platform", "tapeout-authority", "firmware-platform", "fab-site", "sort-site", "osat-site", "test-site", "product-owner"}
)

const (
	calUnit  = "CLP-00002"
	calOther = "CLP-00005"
	testCA   = "HSLSA Test IDevID CA"
)

// reendorse issues every unit's IDevID certificate from its CSR with the CA key in caDir.
func reendorse(bundle, caDir string) error {
	caKey, err := loadECKey(filepath.Join(caDir, "identity-ca.key.pem"))
	if err != nil {
		return err
	}
	csrs, err := filepath.Glob(filepath.Join(bundle, "artifacts", "identity", "*.csr.der"))
	if err != nil {
		return err
	}
	for _, path := range csrs {
		der, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			return err
		}
		cert, err := Endorse(csr, caKey, testCA)
		if err != nil {
			return err
		}
		unit := strings.TrimSuffix(filepath.Base(path), ".csr.der")
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), unit+".idevid.der"), cert, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func resignFile(path, key string, mutate func(Obj)) error {
	stmt, err := DecodeEnvelope(path)
	if err != nil {
		return err
	}
	if mutate != nil {
		mutate(stmt)
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	_, err = Sign(stmt, signer, path)
	return err
}

// resignCoRIM re-issues the firmware CoRIM with role's key in keys, holding
// mutate's reference values (the current ones when mutate is nil), then
// re-signs the bundle provenance with the firmware platform's key to name it.
func resignCoRIM(bundle, keys, role string, mutate func([]RefValue) []RefValue) error {
	path := filepath.Join(bundle, "artifacts", CoRIMFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	c, err := ParseCoRIM(data)
	if err != nil {
		return err
	}
	refs := c.RefValues
	if mutate != nil {
		refs = mutate(refs)
	}
	signer, err := LoadSigner(filepath.Join(keys, role+".key.pem"))
	if err != nil {
		return err
	}
	if err := WriteCoRIM(path, c.ID, "HSLSA firmware build platform", "firmware-platform", refs, signer); err != nil {
		return err
	}
	corimRD, err := fileRD(path, "")
	if err != nil {
		return err
	}
	return resignFile(filepath.Join(bundle, "att", FWAtt["bundle"]), filepath.Join(keys, "firmware-platform.key.pem"), func(s Obj) {
		for _, b := range Objs(s, "predicate", "runDetails", "byproducts") {
			if S(b, "name") == CoRIMFile {
				b["digest"] = corimRD["digest"]
			}
		}
	})
}

// calRebuild re-signs the chain downstream of the design steps and firmware provenance with the test keys.
func calRebuild(bundle string, fromRomMerge bool) error {
	keys := filepath.Join(filepath.Dir(bundle), "keys")
	if fromRomMerge {
		romEnv := envRD(bundle, FWAtt["rom"])
		err := resignFile(filepath.Join(bundle, "att", AttName("rom-merge")), filepath.Join(keys, "flow-platform.key.pem"), func(s Obj) {
			for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
				if S(d, "name") == S(romEnv, "name") {
					d["digest"] = romEnv["digest"]
				}
			}
		})
		if err != nil {
			return err
		}
	}
	if err := CaliptraRelease(bundle, filepath.Join(keys, "tapeout-authority.key.pem"), filepath.Join(bundle, "trust-root.json"), calPolicy); err != nil {
		return err
	}
	if err := Mfg(bundle, calScenario, keys, nil); err != nil {
		return err
	}
	if err := SignProvisioning(bundle, filepath.Join(keys, "test-site.key.pem")); err != nil {
		return err
	}
	return CaliptraHBOM(bundle, calLock, calScenario, filepath.Join(keys, "product-owner.key.pem"))
}

func calSource() string { return envPath("HSLSA_CALIPTRA_OUT", "out/caliptra") }

func requireCaliptraRun(t *testing.T, src string) {
	t.Helper()
	requireDir(t, filepath.Join(src, "bundle", "att"), "run e2e/caliptra/run.sh produce and verify first")
	requireDir(t, filepath.Join(src, "boots"), "run e2e/caliptra/run.sh produce and verify first")
}

// calWork is a fresh copy of a work directory holding bundle/, boots/ and keys/.
func calWork(t *testing.T) string {
	t.Helper()
	src := calSource()
	requireCaliptraRun(t, src)
	valid := shared(t, "caliptra", func(work string) error {
		bundle := filepath.Join(work, "bundle")
		if err := copyTree(filepath.Join(src, "bundle"), bundle); err != nil {
			return err
		}
		if err := copyTree(filepath.Join(src, "boots"), filepath.Join(work, "boots")); err != nil {
			return err
		}
		keys, pub := filepath.Join(work, "keys"), filepath.Join(work, "pub")
		if err := makeKeys(keys, pub, calRoles...); err != nil {
			return err
		}
		if _, err := Keygen(keys, "attacker"); err != nil {
			return err
		}
		if err := IdentityCA(keys, testCA); err != nil {
			return err
		}
		if err := IdentityCA(filepath.Join(keys, "attacker-ca"), testCA); err != nil {
			return err
		}
		if err := copyFile(filepath.Join(keys, "identity-ca.pub.pem"), filepath.Join(pub, "identity-ca.pub.pem")); err != nil {
			return err
		}
		if err := BuildTrustRoot(pub, filepath.Join(bundle, "trust-root.json")); err != nil {
			return err
		}
		if err := resignFile(filepath.Join(bundle, "att", FWAtt["rom"]), filepath.Join(keys, "firmware-platform.key.pem"), nil); err != nil {
			return err
		}
		if err := resignCoRIM(bundle, keys, "firmware-platform", nil); err != nil {
			return err
		}
		for _, step := range []string{"source-freeze", "simulation"} {
			if err := resignFile(filepath.Join(bundle, "att", AttName(step)), filepath.Join(keys, "flow-platform.key.pem"), nil); err != nil {
				return err
			}
		}
		if err := reendorse(bundle, keys); err != nil {
			return err
		}
		return calRebuild(bundle, true)
	})
	return copyOf(t, valid)
}

func calCheck(t *testing.T, work string, units []string, policy string) error {
	t.Helper()
	if units == nil {
		units = ok(ReadUnits(filepath.Join(calDir, "received-units.txt")))
	}
	if policy == "" {
		policy = calPolicy
	}
	unitsFile := writeLines(t, filepath.Join(t.TempDir(), "units.txt"), units)
	bundle := filepath.Join(work, "bundle")
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	return CaliptraVerify(bundle, trust, policy, unitsFile, filepath.Join(work, "boots"), "", "")
}

func calRejects(t *testing.T, work, reason string) {
	t.Helper()
	rejects(t, calCheck(t, work, nil, ""), reason)
}

func calResign(t *testing.T, work, name, role string, mutate func(Obj)) {
	t.Helper()
	resign(t, filepath.Join(work, "bundle", "att", name), filepath.Join(work, "keys"), role, mutate)
}

func TestProducedCaliptraRunVerifiesAsIs(t *testing.T) {
	src := calSource()
	requireCaliptraRun(t, src)
	must(t, calCheck(t, src, nil, ""))
}

func TestRebuiltCaliptraBundleVerifies(t *testing.T) {
	must(t, calCheck(t, calWork(t), nil, ""))
}

// The device

func TestCertificateFromAnotherUnit(t *testing.T) {
	work := calWork(t)
	must(t, copyFile(filepath.Join(work, "boots", calOther, "ldevid-ecc384.der"), filepath.Join(work, "boots", calUnit, "ldevid-ecc384.der")))
	calRejects(t, work, "device "+calUnit+": UEID in the ldevid certificate does not name this unit")
}

func TestMissingAliasCertificate(t *testing.T) {
	work := calWork(t)
	must(t, os.Remove(filepath.Join(work, "boots", calUnit, "rt-alias-ecc384.der")))
	calRejects(t, work, "device "+calUnit+": no rt-alias certificate from the device")
}

func TestLDevIDNotSignedByIDevID(t *testing.T) {
	// An LDevID certificate with the right names and serial, signed by a key that is not the unit's IDevID.
	work := calWork(t)
	path := filepath.Join(work, "boots", calUnit, "ldevid-ecc384.der")
	real := ok(loadCert(path))
	other := ok(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	tmpl := &x509.Certificate{
		SerialNumber:       real.SerialNumber,
		RawSubject:         real.RawSubject,
		NotBefore:          real.NotBefore,
		NotAfter:           time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC),
		ExtraExtensions:    real.Extensions,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	parent := &x509.Certificate{RawSubject: real.RawIssuer, PublicKey: &other.PublicKey}
	must(t, os.WriteFile(path, ok(x509.CreateCertificate(rand.Reader, tmpl, parent, real.PublicKey, other)), 0o644))
	calRejects(t, work, "device "+calUnit+" LDevID: signature does not verify under the parent key")
}

func TestReceivedUnitThatFailedFinalTest(t *testing.T) {
	work := calWork(t)
	rejects(t, calCheck(t, work, []string{calUnit, "CLP-00006"}, ""), "received unit CLP-00006 is not in the shipped lot")
}

// Provisioning and identity

func TestProvisioningRecordOfAnotherUnit(t *testing.T) {
	work := calWork(t)
	att := filepath.Join(work, "bundle", "att")
	must(t, copyFile(filepath.Join(att, ProvAtt(calOther)), filepath.Join(att, ProvAtt(calUnit))))
	calRejects(t, work, "provisioning record is for urn:hslsa:unit:"+calOther)
}

func TestProvisioningRecordSignedByAnotherSite(t *testing.T) {
	work := calWork(t)
	calResign(t, work, ProvAtt(calUnit), "osat-site", nil)
	calRejects(t, work, "no valid signature from role 'test-site'")
}

func TestProvisioningRecordEditedWithoutResigning(t *testing.T) {
	work := calWork(t)
	editPayload(t, filepath.Join(work, "bundle", "att", ProvAtt(calUnit)), func(s Obj) {
		O(s, "predicate", "hwProvision", "fuses")["fw_svn"] = 0
	})
	calRejects(t, work, "no valid signature from role 'test-site'")
}

func TestIDevIDEndorsedByAnotherCA(t *testing.T) {
	work := calWork(t)
	bundle := filepath.Join(work, "bundle")
	must(t, reendorse(bundle, filepath.Join(work, "keys", "attacker-ca")))
	must(t, SignProvisioning(bundle, filepath.Join(work, "keys", "test-site.key.pem")))
	calRejects(t, work, "device "+calUnit+": IDevID certificate is not endorsed by the identity CA")
}

func TestRecordClaimsOtherVendorFuses(t *testing.T) {
	work := calWork(t)
	calResign(t, work, ProvAtt(calUnit), "test-site", func(s Obj) {
		O(s, "predicate", "hwProvision", "fuses")["vendor_pk_hash"] = strings.Repeat("ab", 48)
	})
	calRejects(t, work, "vendor fuses the device measured differ from the provisioning record")
}

func TestRecordClaimsOtherSVNFuse(t *testing.T) {
	work := calWork(t)
	calResign(t, work, ProvAtt(calUnit), "test-site", func(s Obj) {
		O(s, "predicate", "hwProvision", "fuses")["fw_svn"] = 3
	})
	calRejects(t, work, "owner fuses the device measured differ from the provisioning record")
}

func TestRecordNamesAnotherDesign(t *testing.T) {
	work := calWork(t)
	calResign(t, work, ProvAtt(calUnit), "test-site", func(s Obj) {
		O(s, "predicate", "hwProvision", "designRef", "digest")["sha256"] = strings.Repeat("1", 64)
	})
	calRejects(t, work, "provisioning record names a different design release")
}

func TestPolicyMinimumSVNAboveTheImage(t *testing.T) {
	work := calWork(t)
	policy := ok(ReadObj(calPolicy))
	O(policy, "firmware")["minSvn"] = 2
	path := filepath.Join(t.TempDir(), "policy.json")
	must(t, WriteJSON(path, policy))
	rejects(t, calCheck(t, work, nil, path), "image SVN 1 is below the anti-rollback fuse or policy minimum")
}

// Firmware images

func TestFirmwareProvenanceForAnotherFMC(t *testing.T) {
	// Validly signed provenance and manifest for an FMC the device did not run.
	work := calWork(t)
	bundle := filepath.Join(work, "bundle")
	fake := strings.Repeat("5", 96)
	manifestPath := filepath.Join(bundle, "artifacts", "fw-manifest.json")
	editJSON(t, manifestPath, func(m Obj) { O(m, "fmc")["sha384"] = fake })
	manifestRD := ok(fileRD(manifestPath, ""))
	calResign(t, work, FWAtt["bundle"], "firmware-platform", func(s Obj) {
		for _, subj := range Objs(s, "subject") {
			if S(subj, "name") == Images["fmc"] {
				O(subj, "digest")["sha384"] = fake
			}
		}
		for _, b := range Objs(s, "predicate", "runDetails", "byproducts") {
			if S(b, "name") == "fw-manifest.json" {
				b["digest"] = manifestRD["digest"]
			}
		}
	})
	must(t, resignCoRIM(bundle, filepath.Join(work, "keys"), "firmware-platform", func(refs []RefValue) []RefValue {
		refs[0].Digests[0].Digest = fake
		return refs
	}))
	must(t, calRebuild(bundle, false))
	calResign(t, work, "hbom.intoto.json", "product-owner", func(s Obj) {
		for _, f := range Objs(s, "predicate", "firmware") {
			if S(f, "name") == "caliptra-fmc" {
				O(f, "digest")["sha384"] = fake
			}
		}
	})
	// Every record agrees with every other, the CoRIM included; only the device's own measurement catches the lie.
	calRejects(t, work, "device "+calUnit+": FMC measurement matches no reference value in the firmware CoRIM")
}

// The firmware CoRIM

func TestCoRIMFromAnotherSigner(t *testing.T) {
	work := calWork(t)
	bundle := filepath.Join(work, "bundle")
	must(t, resignCoRIM(bundle, filepath.Join(work, "keys"), "attacker", nil))
	must(t, calRebuild(bundle, false))
	calRejects(t, work, "firmware CoRIM: signature does not verify with any allowed key")
}

func TestCoRIMEditedAfterTheBuild(t *testing.T) {
	work := calWork(t)
	appendFile(t, filepath.Join(work, "bundle", "artifacts", CoRIMFile), "\x00")
	calRejects(t, work, "firmware bundle: "+CoRIMFile+" does not match its provenance")
}

func TestCoRIMForAnotherRuntime(t *testing.T) {
	// The firmware platform signs reference values for a runtime its provenance does not name.
	work := calWork(t)
	bundle := filepath.Join(work, "bundle")
	must(t, resignCoRIM(bundle, filepath.Join(work, "keys"), "firmware-platform", func(refs []RefValue) []RefValue {
		refs[1].Digests[0].Digest = strings.Repeat("8", 96)
		return refs
	}))
	must(t, calRebuild(bundle, false))
	calRejects(t, work, "firmware CoRIM: reference values differ from the image provenance")
}

func TestCoRIMAllowsAnOlderSVN(t *testing.T) {
	work := calWork(t)
	bundle := filepath.Join(work, "bundle")
	must(t, resignCoRIM(bundle, filepath.Join(work, "keys"), "firmware-platform", func(refs []RefValue) []RefValue {
		old := CaliptraTcbSVN(0)
		refs[1].SVN = &old
		return refs
	}))
	must(t, calRebuild(bundle, false))
	calRejects(t, work, "firmware CoRIM: reference values differ from the image provenance")
}

func TestCoRIMWithoutTheRuntime(t *testing.T) {
	work := calWork(t)
	bundle := filepath.Join(work, "bundle")
	must(t, resignCoRIM(bundle, filepath.Join(work, "keys"), "firmware-platform", func(refs []RefValue) []RefValue {
		return refs[:1]
	}))
	must(t, calRebuild(bundle, false))
	calRejects(t, work, "firmware CoRIM: reference values differ from the image provenance")
}

func TestHBOMPointsAtAnotherCoRIM(t *testing.T) {
	work := calWork(t)
	calResign(t, work, "hbom.intoto.json", "product-owner", func(s Obj) {
		for _, f := range Objs(s, "predicate", "firmware") {
			if S(f, "name") == "caliptra-runtime" {
				O(f, "referenceValuesRef", "digest")["sha256"] = strings.Repeat("9", 64)
			}
		}
	})
	calRejects(t, work, "hbom: firmware entry caliptra-runtime does not point at the firmware CoRIM")
}

func TestROMThatIsNotTheFrozenImage(t *testing.T) {
	work := calWork(t)
	calResign(t, work, FWAtt["rom"], "firmware-platform", func(s Obj) {
		O(Objs(s, "subject")[0], "digest")["sha384"] = strings.Repeat("6", 96)
	})
	must(t, calRebuild(filepath.Join(work, "bundle"), true))
	calRejects(t, work, "firmware rom: image is not the ROM the Caliptra TAC froze")
}

func TestFirmwareSignedByTheFlowPlatform(t *testing.T) {
	work := calWork(t)
	calResign(t, work, FWAtt["bundle"], "flow-platform", nil)
	calRejects(t, work, "no valid signature from role 'firmware-platform'")
}

func TestSBOMSwapped(t *testing.T) {
	work := calWork(t)
	appendFile(t, filepath.Join(work, "bundle", "artifacts", "sbom-runtime.cdx.json"), "\n")
	calRejects(t, work, "SBOM sbom-runtime.cdx.json is missing or does not match its digest")
}

func TestHBOMListsAnotherRuntime(t *testing.T) {
	work := calWork(t)
	calResign(t, work, "hbom.intoto.json", "product-owner", func(s Obj) {
		for _, f := range Objs(s, "predicate", "firmware") {
			if S(f, "name") == "caliptra-runtime" {
				O(f, "digest")["sha384"] = strings.Repeat("7", 96)
			}
		}
	})
	calRejects(t, work, "hbom: firmware entry caliptra-runtime does not match the image with provenance")
}

// The mask ROM, through the Design track

func TestROMMergeDoesNotConsumeTheROM(t *testing.T) {
	work := calWork(t)
	calResign(t, work, AttName("rom-merge"), "flow-platform", func(s Obj) {
		bd := O(s, "predicate", "buildDefinition")
		var keep []any
		for _, d := range Objs(bd, "resolvedDependencies") {
			if S(d, "name") == RTLTar {
				keep = append(keep, d)
			}
		}
		bd["resolvedDependencies"] = keep
	})
	must(t, calRebuild(filepath.Join(work, "bundle"), false))
	calRejects(t, work, "rom-merge: does not consume the ROM image named by its firmware provenance")
}

func TestROMReadbackFailed(t *testing.T) {
	work := calWork(t)
	calResign(t, work, AttName("rom-merge"), "flow-platform", func(s Obj) {
		for _, c := range Objs(s, "predicate", "hwFlow", "checks") {
			if S(c, "name") == "rom-readback" {
				c["result"] = "fail"
			}
		}
	})
	calRejects(t, work, "design rom-merge: gate failed: rom-readback")
}

func TestReleasedDesignSwapped(t *testing.T) {
	work := calWork(t)
	appendFile(t, filepath.Join(work, "bundle", "artifacts", DesignTar), string(make([]byte, 512)))
	calRejects(t, work, "subject "+DesignTar+" does not match its attested digest")
}

func TestLintFailureRecorded(t *testing.T) {
	work := calWork(t)
	calResign(t, work, AttName("simulation"), "flow-platform", func(s Obj) {
		Objs(s, "predicate", "hwFlow", "checks")[0]["result"] = "fail"
	})
	calRejects(t, work, "design simulation: gate failed: verilator-lint")
}

func TestCaliptraUnitListTampered(t *testing.T) {
	work := calWork(t)
	appendFile(t, filepath.Join(work, "bundle", "artifacts", "shipped-lot.txt"), "CLP-99999\n")
	calRejects(t, work, "shipped lot list does not match the attested lot digest")
}

func TestROMHexRoundTrip(t *testing.T) {
	data := append(bytes.Repeat(func() []byte {
		b := make([]byte, 256)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}(), 3), 1)
	got := ok(ReadRomHex(string(RomHex(data))))
	if !bytes.Equal(got, data) {
		t.Fatal("ROM hex round trip changed the image")
	}
}

func TestFuseInfoDigestChangesWithEveryVendorFuse(t *testing.T) {
	manifest := Obj{"svn": 1, "vendorEccKeyIndex": 0, "vendorPqcKeyIndex": 0}
	fuses := FuseMap("CLP-00001", Obj{"vendorPkHash": strings.Repeat("a", 96), "ownerPkHash": strings.Repeat("b", 96), "pqcKeyType": 1}, "production", 1)
	digests := func(f Obj) [2]string {
		owner, vendor, err := FuseInfoDigests(f, manifest)
		must(t, err)
		return [2]string{owner, vendor}
	}
	with := func(field string, value any) Obj {
		f := Obj{}
		for k, v := range fuses {
			f[k] = v
		}
		f[field] = value
		return f
	}
	base := digests(fuses)
	for field, value := range map[string]any{"vendor_pk_hash": strings.Repeat("c", 96), "life_cycle": "manufacturing", "debug_locked": false} {
		if digests(with(field, value))[1] == base[1] {
			t.Errorf("vendor info digest ignores %s", field)
		}
	}
	if digests(with("fw_svn", 2))[0] == base[0] {
		t.Error("owner info digest ignores fw_svn")
	}
}
