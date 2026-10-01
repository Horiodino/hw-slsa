package hslsa

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The RFC 6962 test leaves (certificate-transparency's merkle tests), and
// the roots of their first n leaves.
var tlogVectorLeaves = []string{
	"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f",
}

var tlogVectorRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func TestMerkleRootVectors(t *testing.T) {
	var leaves [][]byte
	for i, l := range tlogVectorLeaves {
		leaves = append(leaves, leafHash(ok(hex.DecodeString(l))))
		if got := hex.EncodeToString(merkleRoot(leaves)); got != tlogVectorRoots[i] {
			t.Fatalf("root of %d leaves: %s, want %s", i+1, got, tlogVectorRoots[i])
		}
	}
}

func testLeaves(n int) [][]byte {
	var leaves [][]byte
	for i := 0; i < n; i++ {
		leaves = append(leaves, leafHash([]byte(fmt.Sprintf("entry %d", i))))
	}
	return leaves
}

func TestInclusionProofs(t *testing.T) {
	for n := 1; n <= 40; n++ {
		leaves := testLeaves(n)
		root := merkleRoot(leaves)
		for m := 0; m < n; m++ {
			path := inclusionPath(m, leaves)
			if err := VerifyInclusion(uint64(m), uint64(n), leaves[m], path, root); err != nil {
				t.Fatalf("leaf %d of %d: %v", m, n, err)
			}
			if n > 1 && VerifyInclusion(uint64((m+1)%n), uint64(n), leaves[m], path, root) == nil {
				t.Fatalf("leaf %d of %d verifies at another index", m, n)
			}
			if VerifyInclusion(uint64(m), uint64(n), leafHash([]byte("other")), path, root) == nil {
				t.Fatalf("another leaf verifies at %d of %d", m, n)
			}
		}
		if VerifyInclusion(uint64(n), uint64(n), leaves[0], nil, root) == nil {
			t.Fatal("an index outside the tree verifies")
		}
	}
}

func TestConsistencyProofs(t *testing.T) {
	all := testLeaves(40)
	for n := 1; n <= 40; n++ {
		root2 := merkleRoot(all[:n])
		for m := 1; m <= n; m++ {
			root1 := merkleRoot(all[:m])
			proof := consistencyPath(m, all[:n])
			if err := VerifyConsistency(uint64(m), uint64(n), root1, root2, proof); err != nil {
				t.Fatalf("%d to %d: %v", m, n, err)
			}
			// A log that changed an old entry cannot prove it extends the tree it showed before.
			forked := append([][]byte{leafHash([]byte("rewritten"))}, all[1:n]...)
			if m < n && VerifyConsistency(uint64(m), uint64(n), root1, merkleRoot(forked), consistencyPath(m, forked)) == nil {
				t.Fatalf("%d to %d: a rewritten log is consistent", m, n)
			}
		}
	}
}

// tlogWork is a log with three signed records in it, and a trust root with the log's key.
func tlogWork(t *testing.T) (dir string, trust *TrustRoot, records []string) {
	t.Helper()
	dir = t.TempDir()
	keys, pub := filepath.Join(dir, "keys"), filepath.Join(dir, "pub")
	must(t, makeKeys(keys, pub, "firmware-platform", TLogRole, "other-log"))
	must(t, BuildTrustRoot(pub, filepath.Join(dir, "trust-root.json")))
	trust = ok(LoadTrustRoot(filepath.Join(dir, "trust-root.json")))
	must(t, TLogInit(filepath.Join(dir, "log"), "example buyer firmware log"))
	signer := ok(LoadSigner(filepath.Join(keys, "firmware-platform.key.pem")))
	for i := 0; i < 3; i++ {
		stmt := ok(statement([]Obj{rd(fmt.Sprintf("fw-%d.bin", i), sha256Bytes([]byte{byte(i)}))}, SLSAProvenance, Obj{"buildDefinition": Obj{}}))
		path := filepath.Join(dir, "att", fmt.Sprintf("fw-%d.intoto.json", i))
		must(t, os.MkdirAll(filepath.Dir(path), 0o755))
		ok(Sign(stmt, signer, path))
		must(t, TLogAdd(filepath.Join(dir, "log"), filepath.Join(keys, TLogRole+".key.pem"), path))
		records = append(records, path)
	}
	return dir, trust, records
}

func TestTLogInclusion(t *testing.T) {
	dir, trust, records := tlogWork(t)
	origin := "example buyer firmware log"
	for _, r := range records {
		must(t, func() error { _, err := CheckLogged(trust, r, TLogRole, origin, "test"); return err }())
	}
	check := func(path, role, origin string) error {
		_, err := CheckLogged(trust, path, role, origin, "test")
		return err
	}
	rejects(t, check(records[0], TLogRole, "another log"), "not the log the policy names")
	rejects(t, check(records[0], "other-log", origin), "no valid signature from role 'other-log'")
	// A record that was never logged.
	must(t, os.Remove(TLogProofPath(records[1])))
	rejects(t, check(records[1], TLogRole, origin), "is not in a transparency log")
	// The proof of one record kept beside another.
	must(t, copyFile(TLogProofPath(records[0]), TLogProofPath(records[1])))
	rejects(t, check(records[1], TLogRole, origin), "the log entry is not this record")
	// An audit path that does not lead to the root.
	editJSON(t, TLogProofPath(records[2]), func(p Obj) {
		p["leafIndex"] = 1
	})
	rejects(t, check(records[2], TLogRole, origin), "the inclusion proof fails")
	_ = dir
}

func TestTLogConsistency(t *testing.T) {
	dir, trust, _ := tlogWork(t)
	keys, log := filepath.Join(dir, "keys"), filepath.Join(dir, "log")
	logKey := filepath.Join(keys, TLogRole+".key.pem")
	old := filepath.Join(dir, "old.json")
	must(t, TLogCheckpoint(log, logKey, old))
	// The log grows by one record.
	signer := ok(LoadSigner(filepath.Join(keys, "firmware-platform.key.pem")))
	stmt := ok(statement([]Obj{rd("fw-3.bin", sha256Bytes([]byte{3}))}, SLSAProvenance, Obj{"buildDefinition": Obj{}}))
	path := filepath.Join(dir, "att", "fw-3.intoto.json")
	ok(Sign(stmt, signer, path))
	must(t, TLogAdd(log, logKey, path))
	newer, proof := filepath.Join(dir, "new.json"), filepath.Join(dir, "proof.json")
	must(t, TLogCheckpoint(log, logKey, newer))
	must(t, TLogConsistency(log, 3, proof))
	must(t, TLogVerifyConsistency(trust, TLogRole, old, newer, proof))
	// The operator rewrites the first entry and signs a new checkpoint.
	editJSON(t, filepath.Join(log, tlogState), func(s Obj) {
		O(Objs(s, "entries")[0], "record", "digest")["sha256"] = sha256Bytes([]byte("another release"))
	})
	must(t, TLogCheckpoint(log, logKey, newer))
	must(t, TLogConsistency(log, 3, proof))
	rejects(t, TLogVerifyConsistency(trust, TLogRole, old, newer, proof), "does not extend the log of 3")
}
