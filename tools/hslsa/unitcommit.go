package hslsa

// The per-unit commitment (spec, "Per-unit commitment"): final test's record
// carries the root of an RFC 9162 Merkle tree over the units it shipped, and
// each unit ships with its inclusion proof. A buyer holding the F4 record and
// the proofs of its own units checks them against the lot without the unit
// list and without an escrow auditor.
//
// Each leaf is ["hslsa-unit/v1", salt, unit] with a fresh 128-bit salt per
// unit, so the root and the other units' proofs cannot be checked against
// guessed serials. The leaves are shuffled, so a unit's index says nothing
// about its serial's rank, and the tree is padded with random leaves to the
// next power of two, so a proof shows the lot's size only to within a power
// of two.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"path/filepath"
)

const (
	// UnitCommitmentFormat names the commitment block in final test's hwMfg.
	UnitCommitmentFormat = "hslsa-unit-commitment/v1"
	// UnitProofFormat names a unit's inclusion proof file.
	UnitProofFormat = "hslsa-unit-proof/v1"
	unitLeafTag     = "hslsa-unit/v1"
	padLeafTag      = "hslsa-pad/v1"
	// UnitProofDir holds the proofs, one file per unit, under artifacts/.
	UnitProofDir = "unit-proofs"
)

// unitLeaf is the leaf entry for a unit and its salt.
func unitLeaf(salt, unit string) []byte {
	return compactJSON([]any{unitLeafTag, salt, unit})
}

// paddedSize is the next power of two at or above n (n >= 1).
func paddedSize(n int) int {
	if n <= 1 {
		return 1
	}
	return 1 << bits.Len(uint(n-1))
}

// shuffle permutes xs in place with crypto/rand.
func shuffle(xs []int) error {
	for i := len(xs) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		xs[i], xs[j.Int64()] = xs[j.Int64()], xs[i]
	}
	return nil
}

// commitUnits builds the tree over the shipped units, writes each unit's
// proof to artifacts/unit-proofs/<unit>.json, and returns the commitment
// block for final test's record.
func commitUnits(bundle, lotURN string, shipped []string) (Obj, error) {
	if len(shipped) == 0 {
		return nil, fmt.Errorf("no shipped units to commit to")
	}
	size := paddedSize(len(shipped))
	slots := make([]int, size)
	for i := range slots {
		slots[i] = i
	}
	if err := shuffle(slots); err != nil {
		return nil, err
	}
	leaves := make([][]byte, size)
	salts := make([]string, len(shipped))
	for i := range leaves {
		salt, err := newSalt()
		if err != nil {
			return nil, err
		}
		entry := compactJSON([]any{padLeafTag, salt})
		if i < len(shipped) {
			salts[i] = salt
			entry = unitLeaf(salt, shipped[i])
		}
		leaves[slots[i]] = leafHash(entry)
	}
	root := merkleRoot(leaves)
	dir := filepath.Join(bundle, "artifacts", UnitProofDir)
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	for i, unit := range shipped {
		proof := Obj{
			"format":        UnitProofFormat,
			"lot":           lotURN,
			"unit":          unit,
			"salt":          salts[i],
			"leafIndex":     slots[i],
			"treeSize":      size,
			"inclusionPath": hexes(inclusionPath(slots[i], leaves)),
		}
		if err := WriteJSON(filepath.Join(dir, unit+".json"), proof); err != nil {
			return nil, err
		}
	}
	return Obj{"format": UnitCommitmentFormat, "rootHash": hex.EncodeToString(root), "treeSize": size}, nil
}

// UnitProofPath is where a bundle keeps a unit's inclusion proof.
func UnitProofPath(bundle, unit string) string {
	return filepath.Join(bundle, "artifacts", UnitProofDir, unit+".json")
}

// checkUnitProof checks the proof at path for unit against the commitment in
// a final test record already opened, and that both name lotURN.
func checkUnitProof(commitment Obj, lotURN, unit, path, label string) error {
	if S(commitment, "format") != UnitCommitmentFormat {
		return failf("%s: final test carries no per-unit commitment (hwMfg.unitCommitment)", label)
	}
	root, err := hex.DecodeString(S(commitment, "rootHash"))
	size, ok := Int(commitment, "treeSize")
	if err != nil || len(root) != 32 || !ok || size < 1 || size&(size-1) != 0 {
		return failf("%s: the per-unit commitment is malformed (a SHA-256 root over a power-of-two tree)", label)
	}
	proof, err := ReadObj(path)
	if err != nil {
		return failf("%s: no inclusion proof for unit %s (%s)", label, unit, filepath.Base(path))
	}
	if S(proof, "format") != UnitProofFormat {
		return failf("%s: %s is not a unit inclusion proof", label, filepath.Base(path))
	}
	if S(proof, "unit") != unit || S(proof, "lot") != lotURN {
		return failf("%s: the proof is for unit %s of %s, not unit %s of %s", label, S(proof, "unit"), S(proof, "lot"), unit, lotURN)
	}
	if !saltOK(S(proof, "salt")) {
		return failf("%s: unit %s's proof has a salt shorter than 128 bits", label, unit)
	}
	index, ok1 := Int(proof, "leafIndex")
	psize, ok2 := Int(proof, "treeSize")
	path2, err := unhex(Strs(proof, "inclusionPath"))
	if !ok1 || !ok2 || err != nil || psize != size || index < 0 {
		return failf("%s: unit %s's proof is malformed or for another tree size than the commitment", label, unit)
	}
	if err := VerifyInclusion(uint64(index), uint64(size), leafHash(unitLeaf(S(proof, "salt"), unit)), path2, root); err != nil {
		return failf("%s: unit %s is not in the lot final test committed to: %v", label, unit, err)
	}
	return nil
}

// unitCommitmentCheck is the lot receipt check's rule when the policy sets
// manufacturing.unitCommitment: final test commits to its units, and every
// unit checked (the received ones, or every shipped unit when none are
// given) has a proof under that commitment. It returns the proofs it read.
func unitCommitmentCheck(bundle string, policy, f4 Obj, lotURN string, shipped, received []string) ([]Obj, error) {
	if !Truthy(get(policy, "manufacturing", "unitCommitment")) {
		return nil, nil
	}
	label := "final-test"
	commitment := O(f4, "predicate", "hwMfg", "unitCommitment")
	size, _ := Int(commitment, "treeSize")
	if size > 0 && size < int64(len(shipped)) {
		return nil, failf("%s: the per-unit commitment covers at most %d units, the lot ships %d", label, size, len(shipped))
	}
	units := received
	if len(units) == 0 {
		units = shipped
	}
	var inputs []Obj
	for _, u := range units {
		path := UnitProofPath(bundle, u)
		if err := checkUnitProof(commitment, lotURN, u, path, label); err != nil {
			return nil, err
		}
		inputs = append(inputs, Obj{"name": "artifacts/" + UnitProofDir + "/" + u + ".json", "digest": fileDigest(path)})
	}
	return inputs, nil
}

// UnitCheck is a buyer's check without an auditor: the final test record
// verifies under the test site's key in trust, and each unit's proof places it
// in the lot that record committed to.
func UnitCheck(trust *TrustRoot, recordPath string, proofs []string) error {
	f4, err := trust.Open(recordPath, MfgSigner["final-test"], MfgStep)
	if err != nil {
		return err
	}
	if buildType(f4) != mfgStepType("final-test") {
		return failf("%s is not a final test record", filepath.Base(recordPath))
	}
	lot := firstSubject(f4)
	commitment := O(f4, "predicate", "hwMfg", "unitCommitment")
	for _, p := range proofs {
		proof, err := ReadObj(p)
		if err != nil {
			return failf("%s: %v", filepath.Base(p), err)
		}
		if err := checkUnitProof(commitment, S(lot, "name"), S(proof, "unit"), p, "unit check"); err != nil {
			return err
		}
	}
	size, _ := Int(commitment, "treeSize")
	fmt.Printf("unit check: PASSED, %d unit(s) are in %s, as final test committed to (a tree of %d leaves, so at most %d units)\n",
		len(proofs), S(lot, "name"), size, size)
	return nil
}
