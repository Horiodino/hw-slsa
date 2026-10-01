package hslsa

// A private transparency log for firmware releases (spec, Firmware L3:
// "releases appear in a transparency log", and rule 1 under "Core
// requirements": the log may be private, such as an RFC 9162 style log run
// by the buyer or a consortium).
//
// The log is an append-only Merkle tree as RFC 9162 section 2.1 defines it:
// a leaf hash is SHA-256(0x00 || entry), an interior node SHA-256(0x01 ||
// left || right). Each entry names one signed record by the digest of its
// envelope, with the record's predicate type and subjects, so whoever watches
// the log sees every release a signer made. The operator's key (role
// transparency-log in the buyer's trust root) signs a checkpoint, the tree
// size and root hash, after every append.
//
// A record that was logged carries an inclusion proof beside it in the
// bundle (att/<record>.tlog.json): the entry, its index, the audit path, and
// the checkpoint it proves inclusion under. A verifier recomputes the entry
// from the record it holds, checks the checkpoint's signature, and runs the
// audit path up to the checkpoint's root. A consistency proof between two
// checkpoints shows the log only grew between them, which is how a monitor
// that kept an older checkpoint catches a log that rewrote its history or
// shows different trees to different readers.
//
// The log here is a directory (log.json) the operator's tool appends to;
// nothing is sent anywhere.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
)

const (
	// TLogEntryFormat is the form of a log entry.
	TLogEntryFormat = "hslsa-tlog-entry/v1"
	// TLogProofFormat is the form of an inclusion proof kept beside a record.
	TLogProofFormat = "hslsa-tlog-proof/v1"
	// CheckpointType is the predicate type of a signed checkpoint.
	CheckpointType = NS + "/tlog-checkpoint/v0.1"
	// TLogRole signs checkpoints.
	TLogRole  = "transparency-log"
	tlogState = "log.json"
)

// RFC 9162 hashing

func leafHash(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(entry)
	return h.Sum(nil)
}

func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// splitPoint is the largest power of two smaller than n (n > 1).
func splitPoint(n int) int {
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// merkleRoot is MTH over leaf hashes.
func merkleRoot(leaves [][]byte) []byte {
	switch n := len(leaves); n {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return leaves[0]
	default:
		k := splitPoint(n)
		return nodeHash(merkleRoot(leaves[:k]), merkleRoot(leaves[k:]))
	}
}

// inclusionPath is PATH(m, D[n]) over leaf hashes.
func inclusionPath(m int, leaves [][]byte) [][]byte {
	n := len(leaves)
	if n <= 1 {
		return nil
	}
	k := splitPoint(n)
	if m < k {
		return append(inclusionPath(m, leaves[:k]), merkleRoot(leaves[k:]))
	}
	return append(inclusionPath(m-k, leaves[k:]), merkleRoot(leaves[:k]))
}

// consistencyPath is PROOF(m, D[n]) over leaf hashes, for 0 < m <= n.
func consistencyPath(m int, leaves [][]byte) [][]byte {
	return subproof(m, leaves, true)
}

func subproof(m int, leaves [][]byte, whole bool) [][]byte {
	n := len(leaves)
	if m == n {
		if whole {
			return nil
		}
		return [][]byte{merkleRoot(leaves)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(subproof(m, leaves[:k], whole), merkleRoot(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), merkleRoot(leaves[:k]))
}

// VerifyInclusion checks an audit path (RFC 9162, 2.1.3.2): leaf at index
// is in the tree of size whose root is root.
func VerifyInclusion(index, size uint64, leaf []byte, path [][]byte, root []byte) error {
	if index >= size {
		return errors.New("leaf index is not inside the tree")
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return errors.New("the audit path is longer than the tree")
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("the audit path is shorter than the tree")
	}
	if !bytes.Equal(r, root) {
		return errors.New("the audit path does not lead to the root hash")
	}
	return nil
}

// VerifyConsistency checks a consistency proof (RFC 9162, 2.1.4.2): the
// tree of size1 with root1 is a prefix of the tree of size2 with root2.
func VerifyConsistency(size1, size2 uint64, root1, root2 []byte, proof [][]byte) error {
	switch {
	case size1 == 0 || size1 > size2:
		return errors.New("the first tree must be non-empty and no larger than the second")
	case size1 == size2:
		if len(proof) != 0 || !bytes.Equal(root1, root2) {
			return errors.New("two trees of the same size differ")
		}
		return nil
	case len(proof) == 0:
		return errors.New("empty consistency proof")
	}
	if size1&(size1-1) == 0 {
		proof = append([][]byte{root1}, proof...)
	}
	fn, sn := size1-1, size2-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return errors.New("the consistency proof is longer than the tree")
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || !bytes.Equal(fr, root1) || !bytes.Equal(sr, root2) {
		return errors.New("the second tree does not extend the first")
	}
	return nil
}

// Entries

// TLogEntry is the log entry for the signed record at path: the record by
// the digest of its envelope, its predicate type and its subjects.
func TLogEntry(path string) (Obj, error) {
	stmt, err := DecodeEnvelope(path)
	if err != nil {
		return nil, err
	}
	d, err := sha256File(path)
	if err != nil {
		return nil, err
	}
	subjects := []any{}
	for _, s := range Objs(stmt, "subject") {
		subjects = append(subjects, Obj{"name": get(s, "name"), "digest": get(s, "digest")})
	}
	return Obj{
		"format":        TLogEntryFormat,
		"record":        rd(filepath.Base(path), d),
		"predicateType": get(stmt, "predicateType"),
		"subjects":      subjects,
	}, nil
}

// TLogProofPath is where the inclusion proof of the record at path is kept.
func TLogProofPath(path string) string {
	return strings.TrimSuffix(strings.TrimSuffix(path, ".json"), ".intoto") + ".tlog.json"
}

// The operator's log

type tlog struct {
	dir   string
	state Obj
}

func hexes(hs [][]byte) []any {
	out := make([]any, 0, len(hs))
	for _, h := range hs {
		out = append(out, hex.EncodeToString(h))
	}
	return out
}

func unhex(vs []string) ([][]byte, error) {
	var out [][]byte
	for _, v := range vs {
		b, err := hex.DecodeString(v)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("%q is not a SHA-256 hash", v)
		}
		out = append(out, b)
	}
	return out, nil
}

// TLogInit creates an empty log in dir under origin, the name checkpoints carry.
func TLogInit(dir, origin string) error {
	if origin == "" {
		return errors.New("a log needs an origin")
	}
	if _, err := os.Stat(filepath.Join(dir, tlogState)); err == nil {
		return fmt.Errorf("%s already holds a log", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return WriteJSON(filepath.Join(dir, tlogState), Obj{"format": "hslsa-tlog/v1", "origin": origin, "entries": []any{}})
}

func openTLog(dir string) (*tlog, error) {
	state, err := ReadObj(filepath.Join(dir, tlogState))
	if err != nil {
		return nil, fmt.Errorf("transparency log: %w", err)
	}
	return &tlog{dir: dir, state: state}, nil
}

func (l *tlog) leaves() ([][]byte, error) {
	var out [][]byte
	for _, e := range Objs(l.state, "entries") {
		out = append(out, leafHash(compactJSON(e)))
	}
	return out, nil
}

// checkpoint signs the current tree head.
func (l *tlog) checkpoint(signer *Signer) (Obj, error) {
	leaves, err := l.leaves()
	if err != nil {
		return nil, err
	}
	root := hex.EncodeToString(merkleRoot(leaves))
	origin := S(l.state, "origin")
	stmt, err := statement([]Obj{rd("tlog:"+origin, root)}, CheckpointType, Obj{
		"origin": origin, "treeSize": len(leaves), "rootHash": root, "timestamp": Now(),
	})
	if err != nil {
		return nil, err
	}
	tmp := filepath.Join(l.dir, "checkpoint.intoto.json")
	if _, err := Sign(stmt, signer, tmp); err != nil {
		return nil, err
	}
	return ReadObj(tmp)
}

// prove writes the inclusion proof of entry index under a fresh checkpoint.
func (l *tlog) prove(index int, signer *Signer, out string) error {
	leaves, err := l.leaves()
	if err != nil {
		return err
	}
	cp, err := l.checkpoint(signer)
	if err != nil {
		return err
	}
	return WriteJSON(out, Obj{
		"format":        TLogProofFormat,
		"origin":        get(l.state, "origin"),
		"entry":         Objs(l.state, "entries")[index],
		"leafIndex":     index,
		"treeSize":      len(leaves),
		"inclusionPath": hexes(inclusionPath(index, leaves)),
		"checkpoint":    cp,
	})
}

// TLogAdd appends the record at path to the log in dir, has the operator
// sign a new checkpoint with key, and writes the inclusion proof beside the
// record. A record already in the log is not added twice; it gets a proof
// under the new checkpoint.
func TLogAdd(dir, key, path string) error {
	l, err := openTLog(dir)
	if err != nil {
		return err
	}
	entry, err := TLogEntry(path)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	index := -1
	for i, e := range Objs(l.state, "entries") {
		if jsonEqual(e, entry) {
			index = i
		}
	}
	if index < 0 {
		l.state["entries"] = append(Objs(l.state, "entries"), entry)
		index = len(Objs(l.state, "entries")) - 1
		if err := WriteJSON(filepath.Join(dir, tlogState), l.state); err != nil {
			return err
		}
	}
	if err := l.prove(index, signer, TLogProofPath(path)); err != nil {
		return err
	}
	fmt.Printf("transparency log: %s is entry %d of %d in %s\n", filepath.Base(path), index, len(Objs(l.state, "entries")), S(l.state, "origin"))
	return nil
}

// TLogCheckpoint signs and writes the log's current checkpoint.
func TLogCheckpoint(dir, key, out string) error {
	l, err := openTLog(dir)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	cp, err := l.checkpoint(signer)
	if err != nil {
		return err
	}
	return WriteJSON(out, cp)
}

// TLogConsistency writes the consistency proof from the tree of size from to
// the log's current tree.
func TLogConsistency(dir string, from int, out string) error {
	l, err := openTLog(dir)
	if err != nil {
		return err
	}
	leaves, err := l.leaves()
	if err != nil {
		return err
	}
	if from < 1 || from > len(leaves) {
		return fmt.Errorf("the log has %d entries; a consistency proof starts from 1 to %d", len(leaves), len(leaves))
	}
	return WriteJSON(out, Obj{
		"origin": get(l.state, "origin"), "from": from, "to": len(leaves),
		"proof": hexes(consistencyPath(from, leaves)),
	})
}

// The verifier's side

// Checkpoint is a signed tree head, after its signature was checked.
type Checkpoint struct {
	Origin string
	Size   uint64
	Root   []byte
}

// OpenCheckpoint checks a checkpoint envelope against the log role in trust.
func OpenCheckpoint(trust *TrustRoot, raw Obj, role, name string) (*Checkpoint, error) {
	stmt, err := trust.OpenEnvelope(raw, name, role, CheckpointType)
	if err != nil {
		return nil, err
	}
	p := O(stmt, "predicate")
	size, ok := Int(p, "treeSize")
	root, err := hex.DecodeString(S(p, "rootHash"))
	if !ok || size < 1 || err != nil || len(root) != sha256.Size {
		return nil, failf("%s: not a checkpoint of a non-empty tree", name)
	}
	if S(firstSubject(stmt), "digest", "sha256") != S(p, "rootHash") || S(firstSubject(stmt), "name") != "tlog:"+S(p, "origin") {
		return nil, failf("%s: the checkpoint's subject is not its root hash", name)
	}
	return &Checkpoint{Origin: S(p, "origin"), Size: uint64(size), Root: root}, nil
}

// CheckLogged checks that the record at path is in the transparency log the
// policy names: its inclusion proof is beside it, the entry is this record,
// the checkpoint is signed by the log's key and carries the log's origin,
// and the audit path leads from the entry to the checkpoint's root.
func CheckLogged(trust *TrustRoot, path, role, origin, label string) (*Checkpoint, error) {
	proofPath := TLogProofPath(path)
	proof, err := ReadObj(proofPath)
	if err != nil {
		return nil, failf("%s: %s is not in a transparency log (no %s beside it)", label, filepath.Base(path), filepath.Base(proofPath))
	}
	if S(proof, "format") != TLogProofFormat {
		return nil, failf("%s: %s is not an inclusion proof", label, filepath.Base(proofPath))
	}
	want, err := TLogEntry(path)
	if err != nil {
		return nil, err
	}
	if !jsonEqual(O(proof, "entry"), want) {
		return nil, failf("%s: the log entry is not this record (another envelope or other subjects)", label)
	}
	cp, err := OpenCheckpoint(trust, O(proof, "checkpoint"), role, filepath.Base(proofPath)+" checkpoint")
	if err != nil {
		return nil, err
	}
	if cp.Origin != origin {
		return nil, failf("%s: logged in %q, not the log the policy names (%q)", label, cp.Origin, origin)
	}
	index, ok1 := Int(proof, "leafIndex")
	size, ok2 := Int(proof, "treeSize")
	path2, err := unhex(Strs(proof, "inclusionPath"))
	if !ok1 || !ok2 || err != nil || uint64(size) != cp.Size || index < 0 {
		return nil, failf("%s: the inclusion proof is malformed or for another tree size than its checkpoint", label)
	}
	if err := VerifyInclusion(uint64(index), cp.Size, leafHash(compactJSON(want)), path2, cp.Root); err != nil {
		return nil, failf("%s: the inclusion proof fails: %v", label, err)
	}
	return cp, nil
}

// TLogVerifyConsistency checks that the log under the newer checkpoint
// extends the one under the older, with a proof TLogConsistency wrote.
func TLogVerifyConsistency(trust *TrustRoot, role, olderPath, newerPath, proofPath string) error {
	var cps [2]*Checkpoint
	for i, p := range []string{olderPath, newerPath} {
		raw, err := ReadObj(p)
		if err != nil {
			return err
		}
		if cps[i], err = OpenCheckpoint(trust, raw, role, filepath.Base(p)); err != nil {
			return err
		}
	}
	if cps[0].Origin != cps[1].Origin {
		return failf("the checkpoints are from two logs, %q and %q", cps[0].Origin, cps[1].Origin)
	}
	var proof [][]byte
	if cps[0].Size != cps[1].Size {
		p, err := ReadObj(proofPath)
		if err != nil {
			return err
		}
		from, _ := Int(p, "from")
		to, _ := Int(p, "to")
		if uint64(from) != cps[0].Size || uint64(to) != cps[1].Size {
			return failf("the consistency proof runs from %d to %d, the checkpoints are of %d and %d entries", from, to, cps[0].Size, cps[1].Size)
		}
		if proof, err = unhex(Strs(p, "proof")); err != nil {
			return failf("consistency proof: %v", err)
		}
	}
	if err := VerifyConsistency(cps[0].Size, cps[1].Size, cps[0].Root, cps[1].Root, proof); err != nil {
		return failf("the log of %d entries does not extend the log of %d it showed before: %v", cps[1].Size, cps[0].Size, err)
	}
	fmt.Printf("transparency log: %s grew from %d to %d entries without changing any it had\n", cps[1].Origin, cps[0].Size, cps[1].Size)
	return nil
}
