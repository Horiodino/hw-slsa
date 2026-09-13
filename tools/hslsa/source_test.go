package hslsa

// Design L2 tamper tests: the signed tag, the review and the IP vendor's
// provenance. Each forges or breaks one input and requires the tapeout check to
// fail for the stated reason.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitObjectID(t *testing.T) {
	// git hash-object -t blob /dev/null
	if got := gitObjectID("blob", nil); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Fatalf("empty blob id %s", got)
	}
}

func TestSSHSignatureRoundTrip(t *testing.T) {
	keys := t.TempDir()
	s := ok(Keygen(keys, "a"))
	other := ok(Keygen(keys, "b"))
	sig := ok(sshSign(s.priv, "git", []byte("payload\n")))
	if !sshVerify(sig, "git", []byte("payload\n"), []Key{other.Key, s.Key}) {
		t.Fatal("valid signature rejected")
	}
	for name, bad := range map[string]bool{
		"other message":   sshVerify(sig, "git", []byte("payload!\n"), []Key{s.Key}),
		"other key":       sshVerify(sig, "git", []byte("payload\n"), []Key{other.Key}),
		"other namespace": sshVerify(sig, "file", []byte("payload\n"), []Key{s.Key}),
	} {
		if bad {
			t.Errorf("accepted a signature for %s", name)
		}
	}
}

// A tag the Go code signs must pass git's own verify-tag, just as the tags git
// signs pass the Go verifier in the end-to-end run.
func TestSignedTagVerifiesWithGit(t *testing.T) {
	for _, bin := range []string{"git", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is not installed")
		}
	}
	dir := t.TempDir()
	s := ok(Keygen(filepath.Join(dir, "keys"), "source-owner"))
	env := []string{"GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@example.com", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@example.com"}
	ok(gitRun(dir, env, "init", "-q"))
	ok(gitRun(dir, env, "commit", "-q", "--allow-empty", "-m", "x"))
	commit := strings.TrimSpace(string(ok(gitRun(dir, env, "rev-parse", "HEAD"))))
	payload := "object " + commit + "\ntype commit\ntag v1\ntagger a <a@example.com> 0 +0000\n\nv1\n"
	signed := ok(SignTag([]byte(payload), s.priv))
	must(t, os.WriteFile(filepath.Join(dir, "tag.txt"), signed, 0o644))
	id := strings.TrimSpace(string(ok(gitRun(dir, env, "hash-object", "-t", "tag", "-w", "tag.txt"))))
	ok(gitRun(dir, env, "update-ref", "refs/tags/v1", id))
	pub := ok(sshPublicLine(s.Key))
	must(t, os.WriteFile(filepath.Join(dir, "allowed"), []byte("a@example.com "+pub+"\n"), 0o644))
	if _, err := gitRun(dir, env, "-c", "gpg.format=ssh", "-c", "gpg.ssh.allowedSignersFile="+filepath.Join(dir, "allowed"), "verify-tag", "v1"); err != nil {
		t.Fatal(err)
	}
}

// The signed tag

func TestSourceTagSignedByUnknownKey(t *testing.T) {
	bundle := chipBundle(t)
	must(t, retag(bundle, chipKeys(bundle), "attacker", nil))
	rejects(t, chipCheck(t, bundle, nil), "source tag: no valid signature from role 'source-owner'")
}

func TestSourceTagEditedAfterSigning(t *testing.T) {
	bundle := chipBundle(t)
	path := filepath.Join(bundle, "artifacts", sourceGitDir, "tag")
	raw := string(ok(os.ReadFile(path)))
	must(t, os.WriteFile(path, []byte(strings.Replace(raw, "tag picosoc-rtl-v1.0", "tag picosoc-rtl-v1.1", 1)), 0o644))
	rejects(t, chipCheck(t, bundle, nil), "source tag: no valid signature from role 'source-owner'")
}

func TestSourceTagPointsAtAnotherCommit(t *testing.T) {
	bundle := chipBundle(t)
	must(t, retag(bundle, chipKeys(bundle), "source-owner", func(p string) string {
		_, rest, _ := strings.Cut(p, "\n")
		return "object " + strings.Repeat("3", 40) + "\n" + rest
	}))
	rejects(t, chipCheck(t, bundle, nil), "source tag picosoc-rtl-v1.0 points at a different commit")
}

func TestSourceArchiveIsNotTheTaggedTree(t *testing.T) {
	// A flow platform that swaps RTL under the tag signs a record for its own
	// archive; the verifier walks git's hashes from the tag and catches it.
	bundle := chipBundle(t)
	art := filepath.Join(bundle, "artifacts")
	work := t.TempDir()
	must(t, unpack(filepath.Join(art, "source.tar"), work))
	appendFile(t, filepath.Join(work, "picorv32.v"), "// backdoor\n")
	must(t, DeterministicTar(work, ok(tarNames(filepath.Join(art, "source.tar"))), filepath.Join(art, "source.tar")))
	chipResign(t, bundle, AttName("source-freeze"), "flow-platform", func(s Obj) {
		Objs(s, "subject")[0]["digest"] = Obj{"sha256": ok(sha256File(filepath.Join(art, "source.tar")))}
	})
	rejects(t, chipCheck(t, bundle, nil), "source.tar does not match the tree of signed tag picosoc-rtl-v1.0")
}

// The review

func TestSourceReviewSignedByUnknownKey(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, reviewAtt, "attacker", nil)
	rejects(t, chipCheck(t, bundle, nil), "source-review.intoto.json: no valid signature from role 'source-reviewer'")
}

func TestSourceReviewOfAnotherCommit(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, reviewAtt, "source-reviewer", func(s Obj) {
		O(Objs(s, "subject")[0], "digest")["gitCommit"] = strings.Repeat("4", 40)
	})
	rejects(t, chipCheck(t, bundle, nil), "source review covers a different commit than tag picosoc-rtl-v1.0")
}

func TestSourceReviewNotApproved(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, reviewAtt, "source-reviewer", func(s Obj) {
		O(s, "predicate")["decision"] = "changes-requested"
	})
	rejects(t, chipCheck(t, bundle, nil), "source review did not approve commit")
}

func TestSelfReview(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, reviewAtt, "source-reviewer", func(s Obj) {
		O(s, "predicate")["reviewer"] = "Example RTL Engineer <RTL-Engineer@example.com>"
	})
	rejects(t, chipCheck(t, bundle, nil), "source review: reviewer is the commit's author")
}

func TestSourceFreezeSkipsTheReview(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, AttName("source-freeze"), "flow-platform", func(s Obj) {
		bd := O(s, "predicate", "buildDefinition")
		var kept []any
		for _, d := range Objs(bd, "resolvedDependencies") {
			if S(d, "name") != "att/"+reviewAtt {
				kept = append(kept, d)
			}
		}
		bd["resolvedDependencies"] = kept
	})
	rejects(t, chipCheck(t, bundle, nil), "design source-freeze: chain broken, resolvedDependencies do not include source review")
}

// The IP vendor's provenance

func TestIPProvenanceMissing(t *testing.T) {
	bundle := chipBundle(t)
	must(t, os.Remove(filepath.Join(bundle, "att", ipAtt("picorv32"))))
	rejects(t, chipCheck(t, bundle, nil), "missing attestation ip-picorv32.intoto.json")
}

func TestIPProvenanceSignedByTheDesignHouse(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, ipAtt("picorv32"), "flow-platform", nil)
	rejects(t, chipCheck(t, bundle, nil), "ip-picorv32.intoto.json: no valid signature from role 'ip-vendor'")
}

func TestIPIsNotWhatTheVendorReleased(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, ipAtt("picorv32"), "ip-vendor", func(s Obj) {
		O(Objs(s, "subject")[0], "digest")["sha256"] = strings.Repeat("5", 64)
	})
	rejects(t, chipCheck(t, bundle, nil), "ip picorv32: picorv32.v in source.tar does not match the vendor's signed provenance")
}

// The level claim

func TestPolicyClaimsDesignL2WithoutSourceRules(t *testing.T) {
	bundle := chipBundle(t)
	policy := filepath.Join(t.TempDir(), "policy.json")
	must(t, copyFile(e2ePolicy, policy))
	editJSON(t, policy, func(p Obj) { delete(O(p, "design"), "source") })
	rejects(t, chipCheckPolicy(t, bundle, nil, policy), "policy claims Design L2 but does not require a signed, reviewed source freeze")
}

func TestPolicyClaimsDesignL2WithoutIPRules(t *testing.T) {
	bundle := chipBundle(t)
	policy := filepath.Join(t.TempDir(), "policy.json")
	must(t, copyFile(e2ePolicy, policy))
	editJSON(t, policy, func(p Obj) { delete(O(p, "design"), "thirdPartyIP") })
	rejects(t, chipCheckPolicy(t, bundle, nil, policy), "policy claims Design L2 but does not require signed provenance for IP block picorv32")
}
