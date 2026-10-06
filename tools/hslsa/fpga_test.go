package hslsa

// Tests for the FPGA board example (e2e/fpga): the board root of trust rule,
// the images in flash and the at-boot check.
//
// The chain tests need `e2e/fpga/run.sh produce` and `boot` (HSLSA_FPGA_OUT,
// default out/fpga). Each test works on a copy, with the keys the run made,
// so it can forge validly signed records the way an insider could.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var fpgaPolicy = filepath.Join(root, "e2e", "fpga", "policy.json")

func TestNormalizedASC(t *testing.T) {
	routed := ".comment from next-pnr\n.device 5k\n.logic_tile 1 1\n0101\n.sym 3 clk\n.ram_data 6 1\n00ff\n"
	unpacked := ".comment\n.device 5k\n\n.logic_tile 1 1\n0101\n.ram_data 6 1\n00ff\n.ram_data 7 1\n0000\n0000\n"
	if !bytes.Equal(normalizedASC([]byte(routed)), normalizedASC([]byte(unpacked))) {
		t.Fatal("unpacked bitstream differs from the routed design only in what icepack drops")
	}
	changed := strings.Replace(unpacked, "0101", "0111", 1)
	if bytes.Equal(normalizedASC([]byte(routed)), normalizedASC([]byte(changed))) {
		t.Fatal("a changed configuration bit is not noticed")
	}
	lost := strings.Replace(unpacked, "00ff", "0000", 1)
	if bytes.Equal(normalizedASC([]byte(routed)), normalizedASC([]byte(lost))) {
		t.Fatal("lost RAM contents are not noticed")
	}
}

func TestUARTText(t *testing.T) {
	log := "Serial data: 'B'\nSerial data: 'o'\nother\nSerial data: 10\nSerial data: 'k'\n"
	if got := uartText(log); got != "Bo\nk" {
		t.Fatalf("uartText = %q", got)
	}
}

func TestFlashHex(t *testing.T) {
	got := string(FlashHex([]byte{0x13, 0x00, 0xff}, 0x100000))
	if got != "@00100000\n13 00 FF\n" {
		t.Fatalf("FlashHex = %q", got)
	}
}

func TestBoardRefValuesOrder(t *testing.T) {
	refs := BoardRefValues([]Obj{
		{"role": RoleBitstream, "sha256": strings.Repeat("aa", 32)},
		{"role": RoleSoCFW, "sha256": strings.Repeat("bb", 32)},
	}, "V", "P", 3)
	if len(refs) != 2 || refs[0].Env.Type != RoleBitstream || *refs[1].Env.Index != 2 || *refs[0].Env.Layer != 2 || *refs[1].SVN != 3 {
		t.Fatalf("reference values %v", refs)
	}
}

func TestSchemaRootOfTrust(t *testing.T) {
	p := boardPredicate()
	part := Objs(p, "parts")[0]
	part["rootOfTrust"] = Obj{"guards": []any{"U1"}, "images": []any{"a.bin"}}
	must(t, ValidateHBOM(p))
	part["rootOfTrust"] = Obj{"guards": []any{}, "images": []any{"a.bin"}}
	rejects(t, ValidateHBOM(p), "HBOM does not match its schema")
}

// Chain tests

func fpgaSource() string { return envPath("HSLSA_FPGA_OUT", "out/fpga") }

// fpgaWork is a fresh copy of the produced example: the board bundle, the
// programmed boards, what they returned at boot, and every party's keys.
func fpgaWork(t *testing.T) string {
	t.Helper()
	src := fpgaSource()
	requireDir(t, filepath.Join(src, "boots"), "run e2e/fpga/run.sh produce and boot first")
	work := filepath.Join(t.TempDir(), "w")
	for _, d := range []string{"board", "boards", "boots", "keys", "rot-keys"} {
		must(t, copyTree(filepath.Join(src, d), filepath.Join(work, d)))
	}
	return work
}

func fpgaReceived(t *testing.T) []string {
	return ok(ReadUnits(filepath.Join(root, "e2e", "fpga", "received-boards.txt")))
}

func fpgaVerify(t *testing.T, work string) error {
	t.Helper()
	bundle := filepath.Join(work, "board")
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	return FPGAVerify(bundle, trust, fpgaPolicy, filepath.Join(root, "e2e", "fpga", "received-boards.txt"), filepath.Join(work, "boots"), "", "")
}

func fpgaRejects(t *testing.T, work, reason string) {
	t.Helper()
	rejects(t, fpgaVerify(t, work), reason)
}

// fpgaReboot powers a board on again (root of trust only) after a test changed it.
func fpgaReboot(t *testing.T, work, serial string) bool {
	t.Helper()
	out := filepath.Join(work, "boots", serial)
	must(t, os.RemoveAll(out))
	must(t, FPGABoot(filepath.Join(work, "boards", serial), nil, out))
	return Truthy(ok(ReadObj(filepath.Join(out, BootRecord)))["released"])
}

func TestFPGAChainPasses(t *testing.T) {
	work := fpgaWork(t)
	must(t, fpgaVerify(t, work))
	// The platform certificate reports one TcbInfo per image, which the Go
	// side of the example (tcbInfoDER) and the RoT firmware encode alike.
	serial := fpgaReceived(t)[0]
	cert := ok(loadCert(filepath.Join(work, "boots", serial, "platform.der")))
	infos := ok(TcbInfos(cert))
	if len(infos) != 2 || infos[0].Type != RoleBitstream || infos[1].Type != RoleSoCFW || *infos[0].Index != 1 {
		t.Fatalf("platform certificate reports %v", infos)
	}
	want := ok(tcbInfoDER(infos[1].Vendor, infos[1].Model, infos[1].Type, infos[1].SVN, 2, 2, infos[1].FWIDs[0].Digest))
	if !bytes.Contains(cert.Raw, want) {
		t.Fatal("the RoT firmware's TcbInfo encoding differs from tcbInfoDER")
	}
}

// What the root of trust refuses at power on.

func TestRoTHoldsAlteredBitstream(t *testing.T) {
	work := fpgaWork(t)
	serial := fpgaReceived(t)[0]
	path := filepath.Join(work, "boards", serial, FlashImage)
	flash := ok(os.ReadFile(path))
	flash[100] ^= 0x01
	must(t, os.WriteFile(path, flash, 0o644))
	if fpgaReboot(t, work, serial) {
		t.Fatal("the root of trust released an FPGA with an altered bitstream")
	}
	fpgaRejects(t, work, "held the FPGA in reset")
}

func TestRoTHoldsManifestFromAnotherSigner(t *testing.T) {
	// Someone with flash access writes their own images under a manifest signed by their own key.
	work := fpgaWork(t)
	serial := fpgaReceived(t)[0]
	path := filepath.Join(work, "boards", serial, FlashImage)
	flash := ok(os.ReadFile(path))
	lock := ok(ReadObj(filepath.Join(work, "board", FPGADesignDir, "inputs.lock.json")))
	off, _ := Int(lock, "flash", "manifestOffset")
	m := ok(readBootManifest(flash, off))
	payload, _, err := openBlob(m)
	must(t, err)
	must(t, makeKeys(filepath.Join(work, "evil"), filepath.Join(work, "evil-pub"), "attacker"))
	forged := ok(signBlob(payload, ok(LoadSigner(filepath.Join(work, "evil", "attacker.key.pem")))))
	data := compactJSON(forged)
	copy(flash[off+4:], bytes.Repeat([]byte{0xff}, 4092))
	flash[off], flash[off+1], flash[off+2], flash[off+3] = 0, byte(len(data)>>16), byte(len(data)>>8), byte(len(data))
	copy(flash[off+4:], data)
	must(t, os.WriteFile(path, flash, 0o644))
	if fpgaReboot(t, work, serial) {
		t.Fatal("the root of trust released an FPGA under another signer's manifest")
	}
	fpgaRejects(t, work, "held the FPGA in reset")
}

func TestRoTROMRefusesSwappedFirmware(t *testing.T) {
	// A root of trust whose own firmware was replaced: its ROM refuses to run it.
	work := fpgaWork(t)
	serial := fpgaReceived(t)[0]
	fw := filepath.Join(work, "boards", serial, "rot", "flash", RoTFWImage)
	appendFile(t, fw, "patched")
	if fpgaReboot(t, work, serial) {
		t.Fatal("the root of trust ran firmware its vendor did not sign")
	}
	log := string(ok(os.ReadFile(filepath.Join(work, "boots", serial, "rot.log"))))
	if !strings.Contains(log, "not the image its signature names") {
		t.Fatalf("rot.log: %s", log)
	}
	fpgaRejects(t, work, "held the FPGA in reset")
}

func TestRoTHoldsBelowAntiRollbackFuse(t *testing.T) {
	work := fpgaWork(t)
	serial := fpgaReceived(t)[0]
	path := filepath.Join(work, "boards", serial, "rot", "fuses.json")
	fuses := ok(ReadObj(path))
	fuses[ownerFuseSVN] = 2
	must(t, WriteJSON(path, fuses))
	if fpgaReboot(t, work, serial) {
		t.Fatal("the root of trust released images below the anti-rollback fuse")
	}
}

// What the buyer's checks catch.

func TestBootEvidenceFromAnotherBoard(t *testing.T) {
	work := fpgaWork(t)
	r := fpgaReceived(t)
	must(t, os.RemoveAll(filepath.Join(work, "boots", r[1])))
	must(t, copyTree(filepath.Join(work, "boots", r[0]), filepath.Join(work, "boots", r[1])))
	fpgaRejects(t, work, "board "+r[1]+" alias: issuer")
}

func TestSoCDidNotBoot(t *testing.T) {
	work := fpgaWork(t)
	serial := fpgaReceived(t)[0]
	path := filepath.Join(work, "boots", serial, BootRecord)
	rec := ok(ReadObj(path))
	O(rec, "soc")["uartBanner"] = false
	must(t, WriteJSON(path, rec))
	fpgaRejects(t, work, "did not print its boot banner")
}

func fpgaResign(t *testing.T, work, rel, role string, mutate func(Obj)) {
	t.Helper()
	resign(t, filepath.Join(work, "board", rel), filepath.Join(work, "keys"), role, mutate)
}

// ownerResignHBOM is the board owner re-signing its HBOM after mutate (renderings follow).
func ownerResignHBOM(t *testing.T, work string, mutate func(p Obj)) {
	t.Helper()
	bundle := filepath.Join(work, "board")
	stmt := ok(DecodeEnvelope(filepath.Join(bundle, "att", BoardHBOM)))
	mutate(O(stmt, "predicate"))
	delete(O(stmt, "predicate"), "renderings")
	must(t, addRenderings(stmt, filepath.Join(bundle, "att"), "file:att/"))
	ok(Sign(stmt, ok(LoadSigner(filepath.Join(work, "keys", boardOwnerRole+".key.pem"))), filepath.Join(bundle, "att", BoardHBOM)))
}

func rotEntry(p Obj) Obj {
	for _, part := range Objs(p, "parts") {
		if Has(part, "rootOfTrust") {
			return part
		}
	}
	return nil
}

func TestRoTWithoutItsOwnChain(t *testing.T) {
	work := fpgaWork(t)
	ownerResignHBOM(t, work, func(p Obj) { delete(rotEntry(p), "hbomRef") })
	fpgaRejects(t, work, "has no HBOM of its own")
}

func TestRoTThatDoesNotGuardTheFPGA(t *testing.T) {
	work := fpgaWork(t)
	ownerResignHBOM(t, work, func(p Obj) { O(rotEntry(p), "rootOfTrust")["guards"] = []any{"U2"} })
	fpgaRejects(t, work, "does not hold U1 in reset")
}

func TestRoTThatSkipsAnImage(t *testing.T) {
	work := fpgaWork(t)
	ownerResignHBOM(t, work, func(p Obj) { O(rotEntry(p), "rootOfTrust")["images"] = []any{"icebreaker.bin"} })
	fpgaRejects(t, work, "but the board's flash holds")
}

func TestNoRoTMarked(t *testing.T) {
	work := fpgaWork(t)
	ownerResignHBOM(t, work, func(p Obj) { delete(rotEntry(p), "rootOfTrust") })
	fpgaRejects(t, work, "expected one part marked as the board's root of trust, found 0")
}

func TestHBOMListsAnotherBitstream(t *testing.T) {
	work := fpgaWork(t)
	ownerResignHBOM(t, work, func(p Obj) {
		O(Objs(p, "firmware")[0], "digest")["sha256"] = strings.Repeat("ab", 32)
	})
	fpgaRejects(t, work, "firmware entry icebreaker.bin does not match the released image")
}

func TestMissingBoardProvisioning(t *testing.T) {
	work := fpgaWork(t)
	lot := ok(ReadUnits(filepath.Join(work, "board", "artifacts", BoardLot)))
	must(t, os.Remove(filepath.Join(work, "board", "att", BoardProvAtt(lot[1]))))
	fpgaRejects(t, work, "missing attestation "+BoardProvAtt(lot[1]))
}

func TestProvisioningNamesAnotherRoT(t *testing.T) {
	// An EMS insider records another root of trust unit than the one A1 placed.
	work := fpgaWork(t)
	serial := fpgaReceived(t)[0]
	fpgaResign(t, work, "att/"+BoardProvAtt(serial), emsRole, func(s Obj) {
		O(s, "predicate", "hwProvision", "rootOfTrust")["unit"] = "urn:hslsa:unit:EXR01-A0-00008"
	})
	fpgaRejects(t, work, "but A1 placed")
}

func TestBoardWhoseRootOfTrustWasSwapped(t *testing.T) {
	// The roots of trust of the two received boards were swapped after A1
	// recorded the placements, by a rework or a mix-up on the line. The EMS's
	// station reads each part where it is now and every check at the station
	// passes; the board check finds that each record names another unit than
	// the one A1 placed there.
	work := fpgaWork(t)
	bundle, boards := filepath.Join(work, "board"), filepath.Join(work, "boards")
	got := fpgaReceived(t)
	a, b, tmp := filepath.Join(boards, got[0], "rot"), filepath.Join(boards, got[1], "rot"), filepath.Join(work, "swap")
	must(t, os.Rename(a, tmp))
	must(t, os.Rename(b, a))
	must(t, os.Rename(tmp, b))
	export := filepath.Join(work, "ems-station")
	must(t, FPGABoardJob(bundle, filepath.Join(root, "e2e", "fpga", "board-scenario.json"), filepath.Join(work, "keys", "code-signer.pub.pem"), export))
	must(t, ProvisionGate(bundle, icp2Profile, prog01, export))
	must(t, FPGABoardStation(bundle, "", boards, export))
	must(t, ProvisionAdapt(bundle, icp2Profile, prog01, export, filepath.Join(work, "keys", "ems-site.key.pem")))
	placed := ok(rotUnitOn(bundle, got[0], "U5"))
	fpgaRejects(t, work, "but A1 placed "+placed+" at U5")
}

func TestProvisioningBurnsAnotherOwnerKey(t *testing.T) {
	work := fpgaWork(t)
	serial := fpgaReceived(t)[0]
	fpgaResign(t, work, "att/"+BoardProvAtt(serial), emsRole, func(s Obj) {
		O(s, "predicate", "hwProvision", "fuses")[ownerFuseHash] = strings.Repeat("cd", 32)
	})
	fpgaRejects(t, work, "owner key fuse is not the board owner's code signer")
}

func TestProvisioningGateFailed(t *testing.T) {
	work := fpgaWork(t)
	serial := fpgaReceived(t)[0]
	fpgaResign(t, work, "att/"+BoardProvAtt(serial), emsRole, func(s Obj) {
		for _, c := range Objs(s, "predicate", "hwProvision", "checks") {
			if S(c, "name") == "first-boot-released" {
				c["result"] = "fail"
			}
		}
	})
	fpgaRejects(t, work, "provisioning gate failed: first-boot-released")
}

func TestRoTUnitProvisioningGateFailed(t *testing.T) {
	// The root of trust vendor's test site recorded a failed fuse readback for a unit that shipped anyway.
	work := fpgaWork(t)
	serial := fpgaReceived(t)[0]
	unit := ok(rotUnitOn(filepath.Join(work, "board"), serial, "U5"))
	path := filepath.Join(work, "board", "parts", "rot", "att", RoTProvAtt(unit))
	resign(t, path, filepath.Join(work, "rot-keys"), "test-site", func(s Obj) {
		Objs(s, "predicate", "hwProvision", "checks")[2]["result"] = "fail"
	})
	fpgaRejects(t, work, "root of trust "+unit+": provisioning gate failed: fuse-readback")
}

func TestRoTFirmwareSignedByAnotherKey(t *testing.T) {
	work := fpgaWork(t)
	rot := filepath.Join(work, "board", "parts", "rot")
	sig := ok(ReadObj(filepath.Join(rot, "artifacts", RoTFWSig)))
	payload, _, err := openBlob(sig)
	must(t, err)
	must(t, makeKeys(filepath.Join(work, "evil"), filepath.Join(work, "evil-pub"), "attacker"))
	must(t, WriteJSON(filepath.Join(rot, "artifacts", RoTFWSig), ok(signBlob(payload, ok(LoadSigner(filepath.Join(work, "evil", "attacker.key.pem")))))))
	// The firmware platform signs provenance over the new signature file, so only the signer is wrong.
	sigRD := ok(fileRD(filepath.Join(rot, "artifacts", RoTFWSig), ""))
	resign(t, filepath.Join(rot, "att", RoTFWAtt), filepath.Join(work, "rot-keys"), "firmware-platform", func(s Obj) {
		subjects := Objs(s, "subject")
		subjects[1] = sigRD
		s["subject"] = subjects
	})
	fpgaRejects(t, work, "not signed by the vendor's code signer")
}

func TestBoardCoRIMFromAnotherPlatform(t *testing.T) {
	work := fpgaWork(t)
	d := filepath.Join(work, "board", FPGADesignDir)
	rim := ok(ParseCoRIM(ok(os.ReadFile(filepath.Join(d, "artifacts", BoardCoRIMFile)))))
	must(t, makeKeys(filepath.Join(work, "evil"), filepath.Join(work, "evil-pub"), "attacker"))
	must(t, WriteCoRIM(filepath.Join(d, "artifacts", BoardCoRIMFile), "x", "y", "firmware-platform", rim.RefValues,
		ok(LoadSigner(filepath.Join(work, "evil", "attacker.key.pem")))))
	fpgaRejects(t, work, "CoRIM does not match its digest")
}

func TestReleasedBitstreamOnly(t *testing.T) {
	// The firmware platform builds a flash image around a bitstream the tapeout
	// authority never released; the code signer signs its manifest.
	work := fpgaWork(t)
	d := filepath.Join(work, "board", FPGADesignDir)
	bit := filepath.Join(d, "artifacts", "icebreaker.bin")
	released := ok(os.ReadFile(bit))
	must(t, os.WriteFile(bit, append(append([]byte{}, released...), 0), 0o644))
	keys := filepath.Join(work, "keys")
	must(t, FPGAImage(d, filepath.Join(d, "inputs.lock.json"), filepath.Join(root, "e2e", "fpga", "board-scenario.json"),
		filepath.Join(keys, "firmware-platform.key.pem"), filepath.Join(keys, "code-signer.key.pem")))
	must(t, os.WriteFile(bit, released, 0o644))
	fpgaRejects(t, work, "do not include design release, bitstream and firmware icebreaker.bin")
}

func TestUnreadablePlatformCertificate(t *testing.T) {
	work := fpgaWork(t)
	serial := fpgaReceived(t)[0]
	must(t, os.WriteFile(filepath.Join(work, "boots", serial, "platform.der"), []byte("x"), 0o644))
	fpgaRejects(t, work, "no platform certificate from the board")
}

func TestRoTUnitWroteImageWithoutProvenance(t *testing.T) {
	// The vendor's station wrote a third image into the unit that no provenance names.
	work := fpgaWork(t)
	unit := ok(rotUnitOn(filepath.Join(work, "board"), fpgaReceived(t)[0], "U5"))
	path := filepath.Join(work, "board", "parts", "rot", "att", RoTProvAtt(unit))
	resign(t, path, filepath.Join(work, "rot-keys"), "test-site", func(s Obj) {
		hp := O(s, "predicate", "hwProvision")
		hp["images"] = append(A(hp, "images"), Obj{"name": "debug-patch.bin", "digest": Obj{"sha256": strings.Repeat("ee", 32)}, "provenanceVerified": true})
	})
	fpgaRejects(t, work, "root of trust "+unit+": provisioning record wrote other firmware than the image with provenance")
}

func TestRoTUnitImageProvenanceUnchecked(t *testing.T) {
	work := fpgaWork(t)
	unit := ok(rotUnitOn(filepath.Join(work, "board"), fpgaReceived(t)[0], "U5"))
	path := filepath.Join(work, "board", "parts", "rot", "att", RoTProvAtt(unit))
	resign(t, path, filepath.Join(work, "rot-keys"), "test-site", func(s Obj) {
		find(Objs(s, "predicate", "hwProvision", "images"), "name", RoTFWSig)["provenanceVerified"] = false
	})
	fpgaRejects(t, work, "wrote "+RoTFWSig+" without checking its provenance")
}
