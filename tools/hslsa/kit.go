package hslsa

// The pilot kit's own provenance. pilot/make-kit.sh builds a tarball of one
// commit and hslsa binaries; SignKit signs a SLSA provenance statement over
// the tarball and each binary with the kit owner's key, and a detached
// signature over the tarball that openssl can check without trusting anything
// inside it. VerifyKit is the recipient's check of the provenance.

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
)

const (
	// KitBuildType is the provenance buildType of a pilot kit.
	KitBuildType = NS + "/pilot-kit@v1"
	// KitRole is the trust root role whose key signs pilot kits.
	KitRole = "kit-signer"
)

// KitFile is one artifact of a kit: the name it has in the provenance, and
// where it is on disk now.
type KitFile struct {
	Name string
	Path string
}

var gitCommitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// SignKit writes a signed SLSA provenance envelope over files to provenance,
// and, when sigPath is set, the key's ASN.1 ECDSA signature over the first
// file's bytes (SHA-256 for a P-256 key), as `openssl dgst -sha256 -verify`
// checks it.
func SignKit(signer *Signer, commit string, files []KitFile, provenance, sigPath string) error {
	if !gitCommitRE.MatchString(commit) {
		return fmt.Errorf("commit %q is not a full git commit id", commit)
	}
	if len(files) == 0 {
		return fmt.Errorf("no files to sign")
	}
	subjects := make([]Obj, 0, len(files))
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f.Name] {
			return fmt.Errorf("two files named %s", f.Name)
		}
		seen[f.Name] = true
		d, err := fileRD(f.Path, f.Name)
		if err != nil {
			return err
		}
		subjects = append(subjects, d)
	}
	predicate := Obj{
		"buildDefinition": Obj{
			"buildType":          KitBuildType,
			"externalParameters": Obj{"commit": commit, "script": "pilot/make-kit.sh"},
			"internalParameters": Obj{"goVersion": runtime.Version(), "cgo": false},
			"resolvedDependencies": []Obj{{
				"uri":    "git+" + NS,
				"digest": Obj{"gitCommit": commit},
			}},
		},
		"runDetails": builder(),
	}
	stmt, err := statement(subjects, SLSAProvenance, predicate)
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, provenance); err != nil {
		return err
	}
	if sigPath == "" {
		return nil
	}
	data, err := os.ReadFile(files[0].Path)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(context.Background(), data)
	if err != nil {
		return err
	}
	return os.WriteFile(sigPath, sig, 0o644)
}

// VerifyKit checks that provenance was signed by pubPEM's key, describes a
// pilot kit, and names each of files with its current digest. It returns the
// commit the kit was built from.
func VerifyKit(pubPEM, provenance string, files []KitFile) (string, error) {
	text, err := os.ReadFile(pubPEM)
	if err != nil {
		return "", err
	}
	key, err := PublicKeyFromPEM(string(text))
	if err != nil {
		return "", fmt.Errorf("%s: %w", pubPEM, err)
	}
	t := &TrustRoot{Roles: map[string][]Key{KitRole: {key}}}
	stmt, err := t.Open(provenance, KitRole, SLSAProvenance)
	if err != nil {
		return "", err
	}
	if bt := S(stmt, "predicate", "buildDefinition", "buildType"); bt != KitBuildType {
		return "", failf("%s: buildType %s, want %s", provenance, bt, KitBuildType)
	}
	commit := S(stmt, "predicate", "buildDefinition", "externalParameters", "commit")
	if !gitCommitRE.MatchString(commit) {
		return "", failf("%s: no commit in the provenance", provenance)
	}
	want := map[string]string{}
	for _, s := range Objs(stmt, "subject") {
		want[S(s, "name")] = S(s, "digest", "sha256")
	}
	for _, f := range files {
		d, ok := want[f.Name]
		if !ok {
			return "", failf("%s: the provenance does not name %s", provenance, f.Name)
		}
		got, err := sha256File(f.Path)
		if err != nil {
			return "", err
		}
		if got != d {
			return "", failf("%s: sha256 %s, but the provenance says %s", f.Name, got, d)
		}
	}
	return commit, nil
}
