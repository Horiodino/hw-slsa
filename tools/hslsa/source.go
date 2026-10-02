package hslsa

// Design L2 inputs: a signed, reviewed source freeze and signed provenance for
// third-party IP.
//
// Three parties sign here, each with its own key. The design lead commits the
// RTL to the design house's repository and signs a git tag with an SSH key
// (git's own gpg.format=ssh signing). A reviewer signs a source-review record
// for the tagged commit. The IP vendor signs SLSA Provenance for the IP release
// the design house vendored. The verifier checks all three against the trust
// root and walks git's object hashes from the signed tag down to every file in
// the source archive, so the flow platform cannot swap RTL under the tag.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	SourceReviewType = NS + "/source-review/v0.1"
	ipReleaseType    = NS + "/ip-release@v1"
	sourceGitDir     = "source-git"
	reviewAtt        = "source-review.intoto.json"
)

func ipAtt(name string) string { return "ip-" + name + ".intoto.json" }

// Git objects

// gitObjectID is git's SHA-1 object name for raw object content.
func gitObjectID(kind string, data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", kind, len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// gitHeaders parses the header lines of a commit or tag, first value per key.
func gitHeaders(raw []byte) map[string]string {
	out := map[string]string{}
	head, _, _ := bytes.Cut(raw, []byte("\n\n"))
	for _, line := range strings.Split(string(head), "\n") {
		k, v, ok := strings.Cut(line, " ")
		if _, seen := out[k]; ok && !seen {
			out[k] = v
		}
	}
	return out
}

// gitTree parses a raw tree object into path -> blob id. Subdirectories are
// read through subtree, which returns the raw tree object with a given id;
// anything but regular files and directories is refused.
func gitTree(raw []byte, subtree func(id string) ([]byte, error)) (map[string]string, error) {
	out := map[string]string{}
	return out, walkGitTree(raw, "", subtree, out)
}

func walkGitTree(raw []byte, prefix string, subtree func(id string) ([]byte, error), out map[string]string) error {
	for len(raw) > 0 {
		sp := bytes.IndexByte(raw, ' ')
		nul := bytes.IndexByte(raw, 0)
		if sp < 0 || nul < sp || len(raw) < nul+21 {
			return fmt.Errorf("malformed tree object")
		}
		mode, name := string(raw[:sp]), prefix+string(raw[sp+1:nul])
		id := hex.EncodeToString(raw[nul+1 : nul+21])
		raw = raw[nul+21:]
		switch mode {
		case "100644":
			out[name] = id
		case "40000":
			sub, err := subtree(id)
			if err != nil {
				return fmt.Errorf("tree entry %s: %v", name, err)
			}
			if gitObjectID("tree", sub) != id {
				return fmt.Errorf("tree entry %s: subtree object does not match", name)
			}
			if err := walkGitTree(sub, name+"/", subtree, out); err != nil {
				return err
			}
		default:
			return fmt.Errorf("tree entry %s has mode %s, want a regular file or a directory", name, mode)
		}
	}
	return nil
}

// identEmail is the address inside a git identity "Name <email> ...".
func identEmail(ident string) string {
	_, rest, _ := strings.Cut(ident, "<")
	email, _, _ := strings.Cut(rest, ">")
	return strings.ToLower(strings.TrimSpace(email))
}

// SSH signatures (the SSHSIG format git uses with gpg.format=ssh)

const (
	sshsigMagic = "SSHSIG"
	sshsigBegin = "-----BEGIN SSH SIGNATURE-----"
	sshsigEnd   = "-----END SSH SIGNATURE-----"
)

type sshsigBlob struct {
	Version   uint32
	PublicKey []byte
	Namespace string
	Reserved  string
	HashAlg   string
	Signature []byte
}

type sshsigSigned struct {
	Namespace string
	Reserved  string
	HashAlg   string
	Hash      []byte
}

func sshsigData(namespace, hashAlg string, msg []byte) ([]byte, error) {
	var h hash.Hash
	switch hashAlg {
	case "sha512":
		h = sha512.New()
	case "sha256":
		h = sha256.New()
	default:
		return nil, fmt.Errorf("unsupported SSHSIG hash %s", hashAlg)
	}
	h.Write(msg)
	return append([]byte(sshsigMagic), ssh.Marshal(sshsigSigned{namespace, "", hashAlg, h.Sum(nil)})...), nil
}

// sshSign makes an armored SSHSIG signature, as ssh-keygen -Y sign does.
func sshSign(priv crypto.Signer, namespace string, msg []byte) (string, error) {
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return "", err
	}
	data, err := sshsigData(namespace, "sha512", msg)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return "", err
	}
	blob := append([]byte(sshsigMagic), ssh.Marshal(sshsigBlob{
		Version: 1, PublicKey: signer.PublicKey().Marshal(), Namespace: namespace, HashAlg: "sha512", Signature: ssh.Marshal(sig),
	})...)
	b64 := base64.StdEncoding.EncodeToString(blob)
	var out strings.Builder
	out.WriteString(sshsigBegin + "\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	out.WriteString(b64 + "\n" + sshsigEnd + "\n")
	return out.String(), nil
}

// sshVerify checks an armored SSHSIG signature over msg against any of keys.
func sshVerify(armored, namespace string, msg []byte, keys []Key) bool {
	body := strings.TrimSpace(armored)
	if !strings.HasPrefix(body, sshsigBegin) || !strings.HasSuffix(body, sshsigEnd) {
		return false
	}
	body = strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimPrefix(body, sshsigBegin), sshsigEnd)), "")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil || !bytes.HasPrefix(raw, []byte(sshsigMagic)) {
		return false
	}
	var blob sshsigBlob
	if ssh.Unmarshal(raw[len(sshsigMagic):], &blob) != nil || blob.Version != 1 || blob.Namespace != namespace {
		return false
	}
	pub, err := ssh.ParsePublicKey(blob.PublicKey)
	if err != nil {
		return false
	}
	var sig ssh.Signature
	if ssh.Unmarshal(blob.Signature, &sig) != nil {
		return false
	}
	data, err := sshsigData(namespace, blob.HashAlg, msg)
	if err != nil {
		return false
	}
	for _, k := range keys {
		want, err := ssh.NewPublicKey(k.Public)
		if err == nil && bytes.Equal(want.Marshal(), blob.PublicKey) && pub.Verify(data, &sig) == nil {
			return true
		}
	}
	return false
}

// sshPublicLine is a key in OpenSSH authorized_keys form, for an allowed signers file.
func sshPublicLine(k Key) (string, error) {
	pub, err := ssh.NewPublicKey(k.Public)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

// splitSignedTag separates a signed tag object into the signed payload and its SSH signature.
func splitSignedTag(raw []byte) (payload []byte, sig string, ok bool) {
	i := bytes.Index(raw, []byte(sshsigBegin))
	if i <= 0 || raw[i-1] != '\n' {
		return nil, "", false
	}
	return raw[:i], string(raw[i:]), true
}

// SignTag replaces the signature on a tag object with one from priv; tests use
// it to forge tags, and it shows git's format needs nothing but SSHSIG.
func SignTag(payload []byte, priv crypto.Signer) ([]byte, error) {
	sig, err := sshSign(priv, "git", payload)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, payload...), sig...), nil
}

// fetchSources downloads the lock's pinned files into cache (once) and returns their sha256.
func fetchSources(lock Obj, cache string) (map[string]string, error) {
	src := O(lock, "source")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return nil, err
	}
	got := map[string]string{}
	for _, name := range sortedKeys(O(src, "files")) {
		path := filepath.Join(cache, name)
		if _, err := os.Stat(path); err != nil {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return nil, err
			}
			url := strings.NewReplacer("{commit}", S(src, "commit"), "{path}", name).Replace(S(src, "rawUrl"))
			if err := download(url, path); err != nil {
				return nil, err
			}
		}
		d, err := sha256File(path)
		if err != nil {
			return nil, err
		}
		got[name] = d
	}
	return got, nil
}

// Producers

// IPRelease plays the IP vendor: it signs SLSA Provenance for each third-party
// IP block's release files, as the vendor would ship it with the IP.
func IPRelease(bundle, lockPath, key, cache string) error {
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	digests, err := fetchSources(lock, cache)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	src := O(lock, "source")
	for _, ip := range Objs(lock, "ip") {
		started := Now()
		var subjects []Obj
		for _, f := range Strs(ip, "files") {
			if digests[f] == "" {
				return fmt.Errorf("ip %s: %s is not a pinned source file", S(ip, "name"), f)
			}
			subjects = append(subjects, rd(f, digests[f]))
		}
		run := builder()
		O(run, "metadata")["startedOn"] = started
		O(run, "metadata")["finishedOn"] = Now()
		pred := Obj{
			"buildDefinition": Obj{
				"buildType": ipReleaseType,
				"externalParameters": Obj{
					"ip": S(ip, "name"), "supplier": S(ip, "supplier"), "license": S(ip, "license"),
					"repo": S(src, "repo"), "version": S(src, "commit"),
				},
				"resolvedDependencies": []Obj{{
					"uri": "git+" + S(src, "repo") + "@" + S(src, "commit"), "digest": Obj{"gitCommit": S(src, "commit")},
				}},
			},
			"runDetails": run,
		}
		stmt, err := statement(subjects, SLSAProvenance, pred)
		if err != nil {
			return err
		}
		if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", ipAtt(S(ip, "name")))); err != nil {
			return err
		}
		fmt.Printf("ip-release %s: signed by the IP vendor, %d file(s)\n", S(ip, "name"), len(subjects))
	}
	return nil
}

// gitRun runs git in dir with a clean configuration and fixed identities.
func gitRun(dir string, env []string, args ...string) ([]byte, error) {
	base := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C"}
	r, err := runCmd(dir, append(base, env...), "git", args...)
	if err != nil {
		return nil, err
	}
	if r.Code != 0 {
		return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(r.Stderr))
	}
	return []byte(r.Stdout), nil
}

func splitIdent(ident string) (name, email string) {
	name, _, _ = strings.Cut(ident, "<")
	return strings.TrimSpace(name), identEmail(ident)
}

// SourceTag plays the design lead: it commits the pinned RTL to the design
// house's repository and signs a release tag with git's SSH signing, then
// exports the tag, commit and tree objects into the bundle.
func SourceTag(bundle, lockPath, key, cache string) error {
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	fr := O(lock, "freeze")
	if _, err := fetchSources(lock, cache); err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	repo, err := os.MkdirTemp("", "hslsa-rtl-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(repo)
	files := sortedKeys(O(lock, "source", "files"))
	for _, name := range files {
		if err := copyFile(filepath.Join(cache, name), filepath.Join(repo, name)); err != nil {
			return err
		}
	}
	when, err := time.Parse(time.RFC3339, S(fr, "date"))
	if err != nil {
		return fmt.Errorf("freeze.date: %w", err)
	}
	date := fmt.Sprintf("@%d +0000", when.Unix())
	an, ae := splitIdent(S(fr, "author"))
	tn, te := splitIdent(S(fr, "tagger"))
	// OpenSSH reads the signing key from a file; write the same key in its format.
	if _, inFile := signer.priv.(*ecdsa.PrivateKey); !inFile {
		return errors.New("source-tag: git signs with a key file, so the source owner's key cannot be in an HSM here")
	}
	block, err := ssh.MarshalPrivateKey(signer.priv, "")
	if err != nil {
		return err
	}
	keyFile := filepath.Join(repo, ".git-signing-key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	env := []string{
		"GIT_AUTHOR_NAME=" + an, "GIT_AUTHOR_EMAIL=" + ae, "GIT_AUTHOR_DATE=" + date,
		"GIT_COMMITTER_NAME=" + tn, "GIT_COMMITTER_EMAIL=" + te, "GIT_COMMITTER_DATE=" + date,
	}
	tag := S(fr, "tag")
	steps := [][]string{
		{"init", "-q", "-b", "main"},
		append([]string{"add", "--"}, files...),
		{"commit", "-q", "-m", "Freeze RTL for tapeout " + tag},
		{"-c", "gpg.format=ssh", "-c", "user.signingKey=" + keyFile, "tag", "-s", "-m", "RTL freeze " + tag, tag},
	}
	for _, args := range steps {
		if _, err := gitRun(repo, env, args...); err != nil {
			return err
		}
	}
	out := filepath.Join(bundle, "artifacts", sourceGitDir)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	commit, err := gitRun(repo, env, "rev-parse", tag+"^{commit}")
	if err != nil {
		return err
	}
	commitID := strings.TrimSpace(string(commit))
	for name, args := range map[string][]string{
		"tag":    {"cat-file", "tag", tag},
		"commit": {"cat-file", "commit", commitID},
		"tree":   {"cat-file", "tree", commitID + "^{tree}"},
	} {
		raw, err := gitRun(repo, env, args...)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, name), raw, 0o644); err != nil {
			return err
		}
	}
	// Subdirectories: one tree object each, named by its id.
	subtrees, err := gitRun(repo, env, "ls-tree", "-r", "-d", "--format=%(objectname)", commitID)
	if err != nil {
		return err
	}
	for _, id := range strings.Fields(string(subtrees)) {
		raw, err := gitRun(repo, env, "cat-file", "tree", id)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "tree-"+id), raw, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("source-tag: %s signed by the design lead, commit %s\n", tag, commitID)
	return nil
}

// SourceReview plays a reviewer: it signs an approval of the tagged commit.
// reviewer is who approves, as "Name <email>"; empty means the lock's
// reviewer. The lock's reviewer's approval is source-review.intoto.json; a
// further reviewer's (Design L4 asks for two) goes beside it, named after
// that reviewer.
func SourceReview(bundle, lockPath, key, reviewer string) error {
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	fr := O(lock, "freeze")
	if reviewer == "" {
		reviewer = S(fr, "reviewer")
	}
	raw, err := os.ReadFile(filepath.Join(bundle, "artifacts", sourceGitDir, "commit"))
	if err != nil {
		return err
	}
	commitID := gitObjectID("commit", raw)
	pred := Obj{
		"repo":       S(fr, "repo"),
		"reviewer":   reviewer,
		"author":     gitHeaders(raw)["author"],
		"decision":   "approved",
		"scope":      "full tree",
		"reviewedAt": Now(),
	}
	stmt, err := statement([]Obj{{"name": S(fr, "repo"), "digest": Obj{"gitCommit": commitID}}}, SourceReviewType, pred)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	name := reviewAtt
	if identEmail(reviewer) != identEmail(S(fr, "reviewer")) {
		name = reviewAttOf(reviewer)
	}
	if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", name)); err != nil {
		return err
	}
	fmt.Printf("source-review: commit %s approved by %s\n", commitID, identEmail(reviewer))
	return nil
}

// reviewAttOf names the review file of a reviewer other than the lock's.
func reviewAttOf(reviewer string) string {
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '-'
	}, strings.ToLower(identEmail(reviewer)))
	return "source-review-" + name + ".intoto.json"
}

// reviewFiles lists the source reviews in a bundle, the lock reviewer's first.
func reviewFiles(bundle string) []string {
	more, _ := filepath.Glob(filepath.Join(bundle, "att", "source-review-*.intoto.json"))
	var out []string
	if fileExists(filepath.Join(bundle, "att", reviewAtt)) {
		out = append(out, reviewAtt)
	}
	for _, m := range more {
		out = append(out, filepath.Base(m))
	}
	return out
}

// Checks, shared by the source freeze step's gates and the buyer's tapeout check

// checkSourceTag verifies the signed tag and the reviews, and that archive
// holds exactly the tagged tree. It returns the commit, the tag name and the
// review envelopes.
func checkSourceTag(bundle string, trust *TrustRoot, rules Obj, archive string) (string, string, []Obj, error) {
	dir := filepath.Join(bundle, "artifacts", sourceGitDir)
	read := func(name string) ([]byte, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, failf("source tag: %s object is missing from the bundle", name)
		}
		return b, nil
	}
	tagRaw, err := read("tag")
	if err != nil {
		return "", "", nil, err
	}
	commitRaw, err := read("commit")
	if err != nil {
		return "", "", nil, err
	}
	treeRaw, err := read("tree")
	if err != nil {
		return "", "", nil, err
	}
	role := S(rules, "tagSigner")
	payload, sig, ok := splitSignedTag(tagRaw)
	if !ok || !sshVerify(sig, "git", payload, trust.Roles[role]) {
		return "", "", nil, failf("source tag: no valid signature from role '%s'", role)
	}
	th := gitHeaders(payload)
	commitID := gitObjectID("commit", commitRaw)
	if th["type"] != "commit" || th["object"] != commitID {
		return "", "", nil, failf("source tag %s points at a different commit", th["tag"])
	}
	ch := gitHeaders(commitRaw)
	if ch["tree"] != gitObjectID("tree", treeRaw) {
		return "", "", nil, failf("source commit %s: tree object does not match", commitID)
	}
	tree, err := gitTree(treeRaw, func(id string) ([]byte, error) {
		b, err := os.ReadFile(filepath.Join(dir, "tree-"+id))
		if err != nil {
			return nil, fmt.Errorf("subtree object %s is missing from the bundle", id)
		}
		return b, nil
	})
	if err != nil {
		return "", "", nil, failf("source commit %s: %v", commitID, err)
	}
	members, err := tarNames(archive)
	if err != nil {
		return "", "", nil, failf("source freeze: %v", err)
	}
	mismatch := len(members) != len(tree)
	for _, m := range members {
		data, err := tarMember(archive, m)
		if err != nil || tree[m] != gitObjectID("blob", data) {
			mismatch = true
		}
	}
	if mismatch {
		return "", "", nil, failf("%s does not match the tree of signed tag %s", filepath.Base(archive), th["tag"])
	}

	reviews, err := checkReviews(bundle, trust, rules, commitID, ch["author"], th["tag"])
	if err != nil {
		return "", "", nil, err
	}
	return commitID, th["tag"], reviews, nil
}

// checkReviews verifies every source review in the bundle: each is signed by
// a key of the reviewer role, approves the tagged commit, and is not by its
// author; no two share a key or a reviewer. At least rules.minReviewers
// (default one) must approve: two at Design L4, so no one person can freeze
// the source alone.
func checkReviews(bundle string, trust *TrustRoot, rules Obj, commitID, author, tag string) ([]Obj, error) {
	role := S(rules, "reviewer")
	need := int64(1)
	if n, ok := Int(rules, "minReviewers"); ok && n > need {
		need = n
	}
	files := reviewFiles(bundle)
	if len(files) == 0 {
		return nil, failf("missing attestation %s", reviewAtt)
	}
	keys, people := map[string]string{}, map[string]string{}
	var envs []Obj
	for _, name := range files {
		path := filepath.Join(bundle, "att", name)
		rev, err := trust.Open(path, role, SourceReviewType)
		if err != nil {
			return nil, err
		}
		if S(firstSubject(rev), "digest", "gitCommit") != commitID {
			return nil, failf("source review covers a different commit than tag %s", tag)
		}
		if S(rev, "predicate", "decision") != "approved" {
			return nil, failf("source review did not approve commit %s", commitID)
		}
		who := identEmail(S(rev, "predicate", "reviewer"))
		if who == identEmail(author) {
			return nil, failf("source review: reviewer is the commit's author")
		}
		k, err := trust.SignerKey(path, role)
		if err != nil {
			return nil, err
		}
		if other, ok := keys[k.ID]; ok {
			return nil, failf("source review %s is signed with the same %s key as %s; each review needs its reviewer's own key", name, role, other)
		}
		if other, ok := people[who]; ok {
			return nil, failf("source review %s is by %s, who also signed %s", name, who, other)
		}
		keys[k.ID], people[who] = name, name
		envs = append(envs, envRD(bundle, name))
	}
	if int64(len(envs)) < need {
		return nil, failf("source review: %d reviewer(s) approved commit %s; the policy requires %d (design.source.minReviewers)", len(envs), commitID, need)
	}
	return envs, nil
}

// checkIP verifies each required IP block's vendor provenance and that the
// archive carries exactly the files the vendor released.
func checkIP(bundle string, trust *TrustRoot, blocks []Obj, archive string) ([]Obj, error) {
	var envs []Obj
	for _, ip := range blocks {
		name := S(ip, "name")
		stmt, err := trust.Open(filepath.Join(bundle, "att", ipAtt(name)), S(ip, "signer"), SLSAProvenance)
		if err != nil {
			return nil, err
		}
		label := "ip " + name
		if err := asSLSAProvenance(stmt, label); err != nil {
			return nil, err
		}
		released := map[string]string{}
		for _, s := range Objs(stmt, "subject") {
			released[S(s, "name")] = S(s, "digest", "sha256")
		}
		for _, f := range Strs(ip, "files") {
			data, err := tarMember(archive, f)
			if err != nil || released[f] == "" || released[f] != sha256Bytes(data) {
				return nil, failf("%s: %s in %s does not match the vendor's signed provenance", label, f, filepath.Base(archive))
			}
		}
		envs = append(envs, envRD(bundle, ipAtt(name)))
	}
	return envs, nil
}

// checkSourceFreezeL2 runs both checks on a source freeze record and requires
// the record to consume the tagged commit, the review and the IP provenance.
func checkSourceFreezeL2(bundle string, trust *TrustRoot, pol, stmt Obj) error {
	archive := filepath.Join(bundle, "artifacts", S(firstSubject(stmt), "name"))
	commitID, _, reviews, err := checkSourceTag(bundle, trust, O(pol, "source"), archive)
	if err != nil {
		return err
	}
	ips, err := checkIP(bundle, trust, Objs(pol, "thirdPartyIP"), archive)
	if err != nil {
		return err
	}
	label := "design source-freeze"
	found := false
	for _, d := range Objs(stmt, "predicate", "buildDefinition", "resolvedDependencies") {
		found = found || S(d, "digest", "gitCommit") == commitID
	}
	if !found {
		return failf("%s: chain broken, resolvedDependencies do not include the tagged commit %s", label, commitID)
	}
	if err := requireLink(stmt, label, reviews, "source review"); err != nil {
		return err
	}
	return requireLink(stmt, label, ips, "IP provenance")
}

// sourceFreezeL2Inputs is what a source freeze adds at Design L2: the gates and
// the dependencies on the tag, review and IP provenance.
func sourceFreezeL2Inputs(bundle, trustRoot, policyPath, repo, archive string) ([]Obj, []Obj, error) {
	trust, err := LoadTrustRoot(trustRoot)
	if err != nil {
		return nil, nil, err
	}
	policy, err := ReadObj(policyPath)
	if err != nil {
		return nil, nil, err
	}
	pol := O(policy, "design")
	var deps, checks []Obj
	commitID, tag, reviews, err := checkSourceTag(bundle, trust, O(pol, "source"), archive)
	if err != nil && !IsVerificationError(err) {
		return nil, nil, err
	}
	checks = append(checks, check("signed-reviewed-tag", err == nil, errDetail(err, "tag signed by "+S(pol, "source", "tagSigner")+", commit reviewed by "+S(pol, "source", "reviewer"))))
	if err == nil {
		deps = append(deps, Obj{"uri": "git+" + repo + "@refs/tags/" + tag, "digest": Obj{"gitCommit": commitID}})
		deps = append(deps, reviews...)
	}
	ips, err := checkIP(bundle, trust, Objs(pol, "thirdPartyIP"), archive)
	if err != nil && !IsVerificationError(err) {
		return nil, nil, err
	}
	checks = append(checks, check("third-party-ip-provenance", err == nil, errDetail(err, fmt.Sprintf("%d IP block(s) match signed vendor provenance", len(ips)))))
	return append(deps, ips...), checks, nil
}

func errDetail(err error, okDetail string) string {
	if err != nil {
		return err.Error()
	}
	return okDetail
}
