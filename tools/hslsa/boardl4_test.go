package hslsa

// Tests for Assembly L4: an independent lab commits to its seed before the
// EMS seals the board lot, then X-rays the boards the seed draws, checks
// every marking against the board HBOM and challenges every identity part.
// The fixture is the L3 board lot made again with the lab enrolled under its
// own company and the EMS consuming the lab's commitment.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	boardL4Plan   = filepath.Join(boardDir, "l4", "inspection-plan.json")
	boardL4Policy = filepath.Join(boardDir, "l4", "policy.json")
	boardL4Roles  = append(append([]string{}, boardL3Roles...), InspectionLabRole)
)

func boardL4Org(lab [2]string) map[string][3]string {
	org := map[string][3]string{InspectionLabRole: {lab[0], lab[1], ""}}
	for k, v := range boardL3Org {
		org[k] = v
	}
	return org
}

// boardL4Work is a fresh copy of a work directory holding the inspected
// board lot: chip/, board/, boards/ (as the lab left them), boards-before/
// (the boards as they were before the inspection), keys/ and lab/.
func boardL4Work(t *testing.T) string {
	t.Helper()
	chip := chipL3Bundle(t)
	usePartRoot(t, chip)
	valid := shared(t, "board-l4", func(work string) error {
		if err := copyTree(chip, filepath.Join(work, "chip")); err != nil {
			return err
		}
		if err := copyTree(filepath.Join(filepath.Dir(chip), "parts"), filepath.Join(work, "chip-parts")); err != nil {
			return err
		}
		if err := makeKeys(filepath.Join(work, "keys"), filepath.Join(work, "pub"), append(boardL4Roles, "buyer-root")...); err != nil {
			return err
		}
		tr, err := boardTrustRoot(work, "enrollments", boardL4Roles, boardL4Org(labOrg))
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(work, "board"), 0o755); err != nil {
			return err
		}
		if err := copyFile(tr, filepath.Join(work, "board", "trust-root.json")); err != nil {
			return err
		}
		lab, labKey := filepath.Join(work, "lab"), filepath.Join(work, "keys", InspectionLabRole+".key.pem")
		if err := InspectionCommit(boardL4Plan, "BRD-EXAMPLE-01", labKey, filepath.Join(lab, "seed.hex"), filepath.Join(lab, "commitment.intoto.json")); err != nil {
			return err
		}
		if err := BoardProduceParts(filepath.Join(work, "board"), filepath.Join(work, "chip"), boardScenario, boardDesign, boardL4Policy,
			filepath.Join(work, "keys"), &BoardParts{Chips: filepath.Join(work, "chip-parts"), Boards: filepath.Join(work, "boards"),
				Commitment: filepath.Join(lab, "commitment.intoto.json")}); err != nil {
			return err
		}
		if err := copyTree(filepath.Join(work, "boards"), filepath.Join(work, "boards-before")); err != nil {
			return err
		}
		return InspectBoards(filepath.Join(work, "board"), filepath.Join(work, "boards"), boardL4Plan, filepath.Join(lab, "seed.hex"), labKey)
	})
	work := copyOf(t, valid)
	usePartRoot(t, filepath.Join(work, "board", "parts", "picosoc"))
	return work
}

func boardL4Check(t *testing.T, work, trustPath, policyPath, boards string) error {
	t.Helper()
	if trustPath == "" {
		trustPath = filepath.Join(work, "board", "trust-root.json")
	}
	if policyPath == "" {
		policyPath = boardL4Policy
	}
	if boards == "" {
		boards = receivedBoards(t, work)
	}
	_, err := BoardVerify(filepath.Join(work, "board"), ok(LoadTrustRoot(trustPath)), policyPath, boards, "", "")
	return err
}

func boardInspection(work string) Obj {
	return O(ok(DecodeEnvelope(filepath.Join(work, "board", "att", InspectionAtt))), "predicate", "hwInspection")
}

func boardSampled(work string) []string {
	var out []string
	for _, s := range Objs(boardInspection(work), "samples") {
		out = append(out, S(s, "serial"))
	}
	return out
}

// reinspectBoards runs the lab again on the boards as they were before the
// first inspection, after tamper changed them, and signs a new record.
func reinspectBoards(t *testing.T, work string, tamper func(boards string)) {
	t.Helper()
	boards := filepath.Join(t.TempDir(), "boards")
	must(t, copyTree(filepath.Join(work, "boards-before"), boards))
	tamper(boards)
	must(t, InspectBoards(filepath.Join(work, "board"), boards, boardL4Plan, filepath.Join(work, "lab", "seed.hex"),
		filepath.Join(work, "keys", InspectionLabRole+".key.pem")))
}

// boardL4PolicyWith writes the board L4 policy after mutate, for one test.
func boardL4PolicyWith(t *testing.T, mutate func(p Obj)) string {
	t.Helper()
	p := ok(ReadObj(boardL4Policy))
	mutate(p)
	path := filepath.Join(t.TempDir(), "policy.json")
	must(t, WriteJSON(path, p))
	return path
}

func TestBoardL4Passes(t *testing.T) {
	work := boardL4Work(t)
	must(t, boardL4Check(t, work, "", "", ""))
	hw := boardInspection(work)
	if len(Objs(hw, "samples")) != 2 || Truthy(get(hw, "destructive")) {
		t.Fatalf("the lab inspected %d boards (destructive %v), want 2 and not destructive", len(Objs(hw, "samples")), get(hw, "destructive"))
	}
	// An inspected board is not destroyed, so the buyer may receive it.
	dir := filepath.Join(t.TempDir(), "received")
	for _, serial := range boardSampled(work) {
		must(t, copyTree(filepath.Join(work, "boards", serial), filepath.Join(dir, serial)))
	}
	must(t, boardL4Check(t, work, "", "", dir))
}

// TestBoardL3PolicyAcceptsInspectedLot: a buyer at Assembly L3 is not asked
// for the inspection, and the lot an L4 buyer accepts passes L3 too.
func TestBoardL3PolicyAcceptsInspectedLot(t *testing.T) {
	work := boardL4Work(t)
	must(t, boardL4Check(t, work, "", boardL3Policy, ""))
}

func TestBoardL4Rejects(t *testing.T) {
	cases := map[string]struct {
		edit   func(t *testing.T, work string) (trust, policy, boards string)
		reason string
	}{
		"no-inspection": {func(t *testing.T, w string) (string, string, string) {
			must(t, os.Remove(filepath.Join(w, "board", "att", InspectionAtt)))
			return "", "", ""
		}, "Assembly L4: no inspection record (inspection.intoto.json) from an independent lab"},
		"policy-without-inspection": {func(t *testing.T, w string) (string, string, string) {
			return "", boardL4PolicyWith(t, func(p Obj) { delete(p, "inspection") }), ""
		}, "the policy sets no minimum sample"},
		"sample-below-the-minimum": {func(t *testing.T, w string) (string, string, string) {
			return "", boardL4PolicyWith(t, func(p Obj) { O(p, "inspection")["minSample"] = 4 }), ""
		}, "a sample of 2, below the policy's minimum of 4"},
		"lab-of-the-ems": {func(t *testing.T, w string) (string, string, string) {
			tr := ok(boardTrustRoot(w, "same-org", boardL4Roles, boardL4Org([2]string{"Example EMS", "duns:100000021"})))
			return tr, "", ""
		}, "the organization that holds the ems-site key; L4 needs an independent party"},
		"trust-root-without-the-lab": {func(t *testing.T, w string) (string, string, string) {
			tr := ok(boardTrustRoot(w, "no-lab", boardL3Roles, boardL3Org))
			return tr, "", ""
		}, "no valid signature from role 'inspection-lab'"},
		"commitment-not-consumed": {func(t *testing.T, w string) (string, string, string) {
			boardForge(t, w, func(s Obj) {
				var keep []any
				for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
					if S(d, "name") != "att/"+InspectionCommitmentAtt {
						keep = append(keep, d)
					}
				}
				O(s, "predicate", "buildDefinition")["resolvedDependencies"] = keep
			})
			return "", "", ""
		}, "nothing shows the lab committed to its seed before the lot was sealed"},
		"steered-sample": {func(t *testing.T, w string) (string, string, string) {
			sampled := boardSampled(w)
			var other string
			for _, b := range ok(ReadUnits(filepath.Join(w, "board", "artifacts", BoardLot))) {
				if !contains(sampled, b) {
					other = b
				}
			}
			resign(t, filepath.Join(w, "board", "att", InspectionAtt), filepath.Join(w, "keys"), InspectionLabRole, func(s Obj) {
				smp := Objs(s, "predicate", "hwInspection", "samples")[0]
				smp["unit"], smp["serial"] = other, other
			})
			return "", "", ""
		}, "the units inspected are not the sample the committed seed draws"},
		"no-assembly-track": {func(t *testing.T, w string) (string, string, string) {
			resign(t, filepath.Join(w, "board", "att", InspectionAtt), filepath.Join(w, "keys"), InspectionLabRole, func(s Obj) {
				O(s, "predicate", "hwInspection")["tracks"] = []any{"WAFER"}
			})
			return "", "", ""
		}, "the inspection does not cover the Assembly track"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			work := boardL4Work(t)
			trust, policy, boards := c.edit(t, work)
			rejects(t, boardL4Check(t, work, trust, policy, boards), c.reason)
		})
	}
}

// What the lab finds on the boards it draws. Each tamper changes every board
// the lab could draw, or the boards it does draw, before the inspection.
func TestBoardInspectionFinds(t *testing.T) {
	cases := map[string]struct {
		tamper func(t *testing.T, work, boards string)
		reason string
	}{
		"counterfeit-marking": {func(t *testing.T, w, boards string) {
			for _, serial := range ok(ReadUnits(filepath.Join(w, "board", "artifacts", BoardLot))) {
				editJSON(t, filepath.Join(boards, serial, BoardPhysical), func(b Obj) {
					for _, ref := range sortedKeys(O(b, "placements")) {
						if ref != "U1" {
							O(b, "placements", ref)["dateCode"] = "0901"
							return
						}
					}
				})
			}
		}, "failed inspection: components-authenticated"},
		"part-the-hbom-does-not-list": {func(t *testing.T, w, boards string) {
			for _, serial := range ok(ReadUnits(filepath.Join(w, "board", "artifacts", BoardLot))) {
				editJSON(t, filepath.Join(boards, serial, BoardPhysical), func(b Obj) {
					O(b, "placements", "U1")["mpn"] = "PSOC130-CLONE"
				})
			}
		}, "failed inspection: x-ray-matches-hbom"},
		"missing-part": {func(t *testing.T, w, boards string) {
			for _, serial := range ok(ReadUnits(filepath.Join(w, "board", "artifacts", BoardLot))) {
				editJSON(t, filepath.Join(boards, serial, BoardPhysical), func(b Obj) {
					delete(O(b, "placements"), "U1")
				})
			}
		}, "failed inspection: x-ray-matches-hbom"},
		"identity-part-swapped": {func(t *testing.T, w, boards string) {
			s := boardSampled(w)
			a, b := filepath.Join(boards, s[0], "U1", dieFile), filepath.Join(boards, s[1], "U1", dieFile)
			da, db := ok(os.ReadFile(a)), ok(os.ReadFile(b))
			must(t, os.WriteFile(a, db, 0o644))
			must(t, os.WriteFile(b, da, 0o644))
		}, "U1 does not answer under the certificate its platform certificate names"},
		"board-not-available": {func(t *testing.T, w, boards string) {
			must(t, os.RemoveAll(filepath.Join(boards, boardSampled(w)[0])))
		}, "the board was not available"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			work := boardL4Work(t)
			reinspectBoards(t, work, func(boards string) { c.tamper(t, work, boards) })
			err := boardL4Check(t, work, "", "", "")
			rejects(t, err, c.reason)
			if !strings.Contains(err.Error(), "Assembly L4") {
				t.Fatalf("the refusal does not name Assembly L4: %v", err)
			}
		})
	}
}
