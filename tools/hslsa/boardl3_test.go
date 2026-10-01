package hslsa

// Tamper tests for Assembly L3. The fixture builds the example board on the
// L3 chip lot (chipl3_test.go): the EMS challenges each chip before
// placement, the platform CA signs a certificate per board, and the buyer's
// trust root enrolls the EMS and every shipper at an accredited site.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	boardL3Policy = filepath.Join(boardDir, "l3", "policy.json")
	boardL3Roles  = append(append([]string{}, boardRoles...), platformCARole)
)

// boardL3Org is the company and accreditation each board signer is enrolled with.
var boardL3Org = map[string][3]string{
	"ems-site":        {"Example EMS", "duns:100000021", "ipc-1791"},
	"dist-franchised": {"Example Franchised Distributor", "duns:100000022", "sae-as6496"},
	"dist-broker":     {"Example Components Broker", "duns:100000023", ""},
	"pcb-fab":         {"Example PCB Fab", "duns:100000024", "ipc-1791"},
}

func boardL3TrustRoot(work, name string, org map[string][3]string) (string, error) {
	keys, dir := filepath.Join(work, "keys"), filepath.Join(work, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for _, role := range boardL3Roles {
		e := Enrollment{Role: role, OrgName: "Example Open Silicon Group", OrgID: "duns:100000002", Site: "Example Design Center",
			Custody: "file", NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
		if o, ok := org[role]; ok {
			e.OrgName, e.OrgID, e.Site = o[0], o[1], o[0]
			if o[2] != "" {
				e.Accreditation = Accreditation{Scheme: o[2], ID: strings.ToUpper(role) + "-1"}
			}
		}
		if err := Enroll(filepath.Join(keys, "buyer-root.key.pem"), filepath.Join(keys, role+".pub.pem"), e, filepath.Join(dir, role+".intoto.json")); err != nil {
			return "", err
		}
	}
	out := filepath.Join(work, name+".json")
	_, err := BuildPilotTrustRoot(filepath.Join(keys, "buyer-root.pub.pem"), dir, time.Now(), out)
	return out, err
}

// usePartRoot checks the board's chip under the L3 chip lot's buyer-run
// trust root and L3 policy, for the rest of the test.
func usePartRoot(t *testing.T, chip string) {
	t.Helper()
	before, had := PartRoots["picosoc"]
	PartRoots["picosoc"] = PartRoot{TrustRoot: filepath.Join(chip, "trust-root.json"), Policy: l3Policy}
	t.Cleanup(func() {
		if had {
			PartRoots["picosoc"] = before
		} else {
			delete(PartRoots, "picosoc")
		}
	})
}

// boardL3Work is a fresh copy of a work directory holding chip/ (the L3 chip
// lot) and chip-parts/, board/, boards/ and keys/.
func boardL3Work(t *testing.T) string {
	t.Helper()
	chip := chipL3Bundle(t)
	usePartRoot(t, chip)
	valid := shared(t, "board-l3", func(work string) error {
		if err := copyTree(chip, filepath.Join(work, "chip")); err != nil {
			return err
		}
		if err := copyTree(filepath.Join(filepath.Dir(chip), "parts"), filepath.Join(work, "chip-parts")); err != nil {
			return err
		}
		if err := makeKeys(filepath.Join(work, "keys"), filepath.Join(work, "pub"), append(boardL3Roles, "buyer-root")...); err != nil {
			return err
		}
		tr, err := boardL3TrustRoot(work, "enrollments", boardL3Org)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(work, "board"), 0o755); err != nil {
			return err
		}
		if err := copyFile(tr, filepath.Join(work, "board", "trust-root.json")); err != nil {
			return err
		}
		return BoardProduceParts(filepath.Join(work, "board"), filepath.Join(work, "chip"), boardScenario, boardDesign, boardL3Policy,
			filepath.Join(work, "keys"), &BoardParts{Chips: filepath.Join(work, "chip-parts"), Boards: filepath.Join(work, "boards")})
	})
	work := copyOf(t, valid)
	usePartRoot(t, filepath.Join(work, "board", "parts", "picosoc"))
	return work
}

// receivedBoards copies the example's received boards out of boards/.
func receivedBoards(t *testing.T, work string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "received")
	for _, serial := range ok(ReadUnits(filepath.Join(boardDir, "received-boards.txt"))) {
		must(t, copyTree(filepath.Join(work, "boards", serial), filepath.Join(dir, serial)))
	}
	return dir
}

func boardL3Check(t *testing.T, work, trustPath, boards string) error {
	t.Helper()
	_, err := BoardVerify(filepath.Join(work, "board"), ok(LoadTrustRoot(trustPath)), boardL3Policy, boards, "", "")
	return err
}

func boardL3Default(t *testing.T, work string) error {
	t.Helper()
	return boardL3Check(t, work, filepath.Join(work, "board", "trust-root.json"), receivedBoards(t, work))
}

// boardForge re-signs A1 after mutate, then the platform certificates and
// the board HBOM over it, as an EMS working with the board owner could.
func boardForge(t *testing.T, work string, mutate func(Obj)) {
	t.Helper()
	b, keys := filepath.Join(work, "board"), filepath.Join(work, "keys")
	resign(t, filepath.Join(b, "att", BoardA1), keys, "ems-site", func(s Obj) {
		if mutate != nil {
			mutate(s)
		}
		refresh(b, s)
	})
	a1 := relRD(b, "att/"+BoardA1)
	for _, f := range ok(filepath.Glob(filepath.Join(b, "att", "platform-*.intoto.json"))) {
		resign(t, f, keys, platformCARole, func(s Obj) { O(s, "predicate", "assemblyRef")["digest"] = a1["digest"] })
	}
	resign(t, filepath.Join(b, "att", BoardHBOM), keys, "board-owner", func(s Obj) {
		O(s, "predicate", "manufacturing", "boardAssembly", "attestationRef")["digest"] = a1["digest"]
	})
}

func TestBoardL3Passes(t *testing.T) {
	work := boardL3Work(t)
	must(t, boardL3Default(t, work))
}

func TestBoardL3Rejects(t *testing.T) {
	cases := map[string]struct {
		edit   func(t *testing.T, work string)
		reason string
	}{
		"no-attestation-at-build": {func(t *testing.T, w string) {
			boardForge(t, w, func(s Obj) {
				var keep []any
				for _, sub := range Objs(s, "subject") {
					if S(sub, "name") != PartAttestations {
						keep = append(keep, sub)
					}
				}
				s["subject"] = keep
			})
		}, "the received units were listed, not challenged"},
		"answer-at-build-forged": {func(t *testing.T, w string) {
			path := filepath.Join(w, "board", "artifacts", PartAttestations)
			editJSON(t, path, func(a Obj) {
				chips := O(a, "chips")
				first, second := O(chips, sortedKeys(chips)[0]), O(chips, sortedKeys(chips)[1])
				first["signature"] = second["signature"]
			})
			boardForge(t, w, nil)
		}, "the answer at build does not verify under the part's certificate"},
		"placed-chip-not-the-one-challenged": {func(t *testing.T, w string) {
			path := filepath.Join(w, "board", "artifacts", PartAttestations)
			editJSON(t, path, func(a Obj) {
				boards := O(a, "boards")
				one, two := O(boards, sortedKeys(boards)[0]), O(boards, sortedKeys(boards)[1])
				one["U1"], two["U1"] = two["U1"], one["U1"]
			})
			boardForge(t, w, nil)
		}, "the part was not checked by attestation at build"},
		"platform-certificate-names-another-chip": {func(t *testing.T, w string) {
			b := filepath.Join(w, "board")
			serial := ok(ReadUnits(filepath.Join(b, "artifacts", BoardLot)))[0]
			resign(t, filepath.Join(b, "att", PlatformCertAtt(serial)), filepath.Join(w, "keys"), platformCARole, func(s Obj) {
				for _, c := range Objs(s, "predicate", "components") {
					if S(c, "refDes") == "U1" {
						O(c, "identity", "certificateDigest")["sha256"] = strings.Repeat("3", 64)
					}
				}
			})
		}, "the platform certificate's U1 is not the part placed there"},
		"platform-certificate-missing": {func(t *testing.T, w string) {
			b := filepath.Join(w, "board")
			serial := ok(ReadUnits(filepath.Join(b, "artifacts", BoardLot)))[0]
			must(t, os.Remove(filepath.Join(b, "att", PlatformCertAtt(serial))))
		}, "missing attestation platform-"},
		"platform-certificate-by-the-ems": {func(t *testing.T, w string) {
			b := filepath.Join(w, "board")
			serial := ok(ReadUnits(filepath.Join(b, "artifacts", BoardLot)))[0]
			resign(t, filepath.Join(b, "att", PlatformCertAtt(serial)), filepath.Join(w, "keys"), "ems-site", nil)
		}, "no valid signature from role 'platform-ca'"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			work := boardL3Work(t)
			c.edit(t, work)
			rejects(t, boardL3Default(t, work), c.reason)
		})
	}
}

func TestBoardL3AtReceipt(t *testing.T) {
	work := boardL3Work(t)
	trustPath := filepath.Join(work, "board", "trust-root.json")
	// Serials typed into a list are not a receipt check at L3.
	rejects(t, boardL3Check(t, work, trustPath, filepath.Join(boardDir, "received-boards.txt")), "listed, not challenged")
	// A chip swapped after build: another genuine chip of the lot in U1.
	boards := receivedBoards(t, work)
	serial := ok(ReadUnits(filepath.Join(boardDir, "received-boards.txt")))[0]
	u1 := filepath.Join(boards, serial, "U1")
	must(t, os.RemoveAll(u1))
	must(t, copyTree(filepath.Join(work, "chip-parts", "PSOC130-A0-00030"), u1))
	rejects(t, boardL3Check(t, work, trustPath, boards), "not the one its records name")
	// A board whose chip was taken off.
	must(t, os.RemoveAll(u1))
	rejects(t, boardL3Check(t, work, trustPath, boards), "does not answer an identity challenge")
}

func TestBoardL3SitesAccredited(t *testing.T) {
	work := boardL3Work(t)
	for name, role := range map[string]string{"ems": "ems-site", "distributor": "dist-franchised"} {
		t.Run(name, func(t *testing.T) {
			org := map[string][3]string{}
			for k, v := range boardL3Org {
				org[k] = v
			}
			org[role] = [3]string{org[role][0], org[role][1], ""}
			tr := ok(boardL3TrustRoot(work, "unaccredited-"+name, org))
			rejects(t, boardL3Check(t, work, tr, receivedBoards(t, work)), "enrolled with no accreditation")
		})
	}
}
