package hslsa

// OCP S.A.F.E. short-form reports, the evidence for Firmware L3 review
// (spec: Firmware review). A review provider publishes its report in one of
// two forms, and the verifier takes either as published:
//
//	jws    the JSON report signed as a compact JWS, the form of every report
//	       in OCP-Security-SAFE/Reports today
//	corim  the S.A.F.E. CoRIM profile (OID 1.3.6.1.4.1.42623.1.1) signed as
//	       COSE_Sign1: the firmware digests are the condition of a
//	       conditional endorsement triple, and the report fields its
//	       endorsement, under measurement-values key -1
//
// A report counts for an image when the three checks in AcceptSFR pass. The
// reference tool also signs both forms, for the Caliptra example's simulated
// review provider: no review provider has reviewed the images it builds.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

const (
	SFRFormatJWS   = "jws"
	SFRFormatCoRIM = "corim"
	// ReviewDir is where a bundle carries the S.A.F.E. reports for its firmware.
	ReviewDir = "review"
	sfrDate   = "2006-01-02"
)

// sfrProfileOID is the S.A.F.E. profile OID. The profile specification and
// OcpReportLib put its full DER encoding, tag and length included, in CBOR
// tag 111; RFC 9090 puts only the contents. A verifier accepts both.
var sfrProfileOID = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xf4, 0x17, 0x01, 0x01}

// SFRIssue is one open issue in a report.
type SFRIssue struct {
	Title, Description, CVSSScore, CVSSVector, CWE, CVE string
}

// SFR is a parsed short-form report, signature not yet checked.
type SFR struct {
	Format           string
	KeyID            string
	FrameworkVersion string
	ReportVersion    string
	Provider         string
	CompletionDate   string
	Scope            int64
	// Digests are the firmware digests the report names, by algorithm
	// (sha256, sha384, sha512), as lowercase hex.
	Digests map[string][]string
	// Manifest is set when the report's digests cover a source manifest
	// rather than an image; such a report names no image digest.
	Manifest bool
	Issues   []SFRIssue

	alg   string // JWS algorithm
	input []byte // JWS signing input
	sig   []byte
	cose  *cose.Sign1Message
}

// ParseSFR decodes a signed report in either form.
func ParseSFR(data []byte) (*SFR, error) {
	if len(data) > 0 && (data[0] == 0xd2 || data[0] == 0x84) {
		return parseSFRCoRIM(data)
	}
	return parseSFRJWS(data)
}

// ReadSFR reads and decodes a signed report.
func ReadSFR(path string) (*SFR, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSFR(data)
}

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func parseSFRJWS(data []byte) (*SFR, error) {
	parts := strings.Split(strings.TrimSpace(string(data)), ".")
	if len(parts) != 3 {
		return nil, errors.New("neither a COSE_Sign1 CoRIM nor a compact JWS")
	}
	hdrBytes, err := b64url(parts[0])
	if err != nil {
		return nil, fmt.Errorf("JWS header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, fmt.Errorf("JWS header: %w", err)
	}
	payload, err := b64url(parts[1])
	if err != nil {
		return nil, fmt.Errorf("JWS payload: %w", err)
	}
	sig, err := b64url(parts[2])
	if err != nil {
		return nil, fmt.Errorf("JWS signature: %w", err)
	}
	v, err := decodeJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("JWS payload: %w", err)
	}
	report, _ := v.(Obj)
	if report == nil {
		return nil, errors.New("JWS payload is not a JSON object")
	}
	r, err := sfrFromJSON(report)
	if err != nil {
		return nil, err
	}
	r.Format, r.KeyID, r.alg, r.sig = SFRFormatJWS, hdr.Kid, hdr.Alg, sig
	r.input = []byte(parts[0] + "." + parts[1])
	return r, nil
}

// sfrFromJSON reads the JSON short-form report, as OcpReportLib writes it.
func sfrFromJSON(rep Obj) (*SFR, error) {
	if !Has(rep, "device") || !Has(rep, "audit") {
		return nil, errors.New("report has no device or audit section")
	}
	r := &SFR{
		FrameworkVersion: S(rep, "review_framework_version"),
		ReportVersion:    S(rep, "audit", "report_version"),
		Provider:         S(rep, "audit", "srp"),
		CompletionDate:   S(rep, "audit", "completion_date"),
		Digests:          map[string][]string{},
	}
	scope, err := scopeNumber(get(rep, "audit", "scope_number"))
	if err != nil {
		return nil, err
	}
	r.Scope = scope
	// With a manifest, the two hashes cover the manifest, not an image.
	r.Manifest = Has(O(rep, "device"), "manifest")
	for alg, field := range map[string]string{"sha384": "fw_hash_sha2_384", "sha512": "fw_hash_sha2_512"} {
		if h := strings.ToLower(S(rep, "device", field)); h != "" && !r.Manifest {
			if err := checkHex(alg, h); err != nil {
				return nil, fmt.Errorf("device.%s: %w", field, err)
			}
			r.Digests[alg] = append(r.Digests[alg], h)
		}
	}
	for _, is := range Objs(rep, "audit", "issues") {
		r.Issues = append(r.Issues, SFRIssue{
			Title: S(is, "title"), Description: S(is, "description"),
			CVSSScore: S(is, "cvss_score"), CVSSVector: S(is, "cvss_vector"),
			CWE: S(is, "cwe"), CVE: S(is, "cve"),
		})
	}
	return r, nil
}

// scopeNumber reads the scope number, a number or, in some published reports, a string.
func scopeNumber(v any) (int64, error) {
	if s, ok := v.(string); ok {
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("scope number %q is not a number", s)
		}
		return n, nil
	}
	if n, ok := Int(v); ok {
		return n, nil
	}
	return 0, nil
}

var digestSize = map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}

func checkHex(alg, h string) error {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != digestSize[alg] {
		return fmt.Errorf("not a %s digest", alg)
	}
	return nil
}

// sfrHashAlg names a CoRIM digest algorithm. The S.A.F.E. example and
// OcpReportLib use COSE algorithm ids (-43, -44); CoRIM's digests-type uses
// the named information registry (1, 7, 8). Both are read.
var sfrHashAlg = map[int64]string{1: "sha256", 7: "sha384", 8: "sha512", -16: "sha256", -43: "sha384", -44: "sha512"}

var sfrDecMode, _ = cbor.DecOptions{IntDec: cbor.IntDecConvertSigned}.DecMode()

// cmap is a decoded CBOR map with integer keys.
type cmap map[any]any

func asCmap(v any) cmap {
	m, _ := v.(map[any]any)
	return m
}

func (m cmap) at(k int64) any { return m[k] }

func untag(v any, num uint64) (any, bool) {
	if t, ok := v.(cbor.Tag); ok {
		if t.Number != num {
			return nil, false
		}
		return t.Content, true
	}
	return v, true
}

func parseSFRCoRIM(data []byte) (*SFR, error) {
	msg := &cose.Sign1Message{}
	if err := msg.UnmarshalCBOR(data); err != nil {
		var untagged cose.UntaggedSign1Message
		if err2 := untagged.UnmarshalCBOR(data); err2 != nil {
			return nil, fmt.Errorf("not a COSE_Sign1: %w", err)
		}
		*msg = cose.Sign1Message(untagged)
	}
	var top any
	if err := sfrDecMode.Unmarshal(msg.Payload, &top); err != nil {
		return nil, fmt.Errorf("CoRIM payload: %w", err)
	}
	content, ok := untag(top, 501)
	corimMap := asCmap(content)
	if !ok || corimMap == nil {
		return nil, errors.New("payload is not a CoRIM map (tag 501)")
	}
	profile, ok := corimMap.at(3).(cbor.Tag)
	oid, _ := profile.Content.([]byte)
	if !ok || profile.Number != 111 || !(bytes.Equal(oid, sfrProfileOID) || bytes.Equal(oid, sfrProfileOID[2:])) {
		return nil, errors.New("CoRIM does not name the S.A.F.E. short-form report profile")
	}
	r := &SFR{Format: SFRFormatCoRIM, cose: msg, Digests: map[string][]string{}}
	if kid, ok := msg.Headers.Unprotected[cose.HeaderLabelKeyID].([]byte); ok {
		r.KeyID = kidString(kid)
	} else if kid, ok := msg.Headers.Protected[cose.HeaderLabelKeyID].([]byte); ok {
		r.KeyID = kidString(kid)
	}
	if ents, _ := corimMap.at(5).([]any); len(ents) > 0 {
		r.Provider, _ = asCmap(ents[0]).at(0).(string)
	}
	var sfrMap cmap
	var digests [][]any
	tags, _ := corimMap.at(1).([]any)
	for _, t := range tags {
		tag, ok := t.(cbor.Tag)
		raw, _ := tag.Content.([]byte)
		if !ok || tag.Number != 506 || raw == nil {
			continue
		}
		var c any
		if err := sfrDecMode.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("CoMID: %w", err)
		}
		triples := asCmap(asCmap(c).at(4))
		records, _ := triples.at(10).([]any)
		for _, rec := range records {
			pair, _ := rec.([]any)
			if len(pair) != 2 {
				return nil, errors.New("malformed conditional endorsement triple")
			}
			conds, _ := pair[0].([]any)
			for _, cond := range conds {
				for _, m := range measurementMaps(cond) {
					ds, _ := asCmap(asCmap(m).at(1)).at(2).([]any)
					for _, d := range ds {
						dl, _ := d.([]any)
						digests = append(digests, dl)
					}
				}
			}
			ends, _ := pair[1].([]any)
			for _, end := range ends {
				for _, m := range measurementMaps(end) {
					if s := asCmap(asCmap(asCmap(m).at(1)).at(-1)); s != nil {
						if sfrMap != nil {
							return nil, errors.New("more than one S.A.F.E. report in one CoRIM")
						}
						sfrMap = s
					}
				}
			}
		}
	}
	if sfrMap == nil {
		return nil, errors.New("CoRIM holds no S.A.F.E. report (measurement-values key -1)")
	}
	r.FrameworkVersion, _ = sfrMap.at(0).(string)
	r.ReportVersion, _ = sfrMap.at(1).(string)
	switch d := sfrMap.at(2).(type) {
	case time.Time:
		r.CompletionDate = d.UTC().Format(sfrDate)
	case cbor.Tag:
		if n, ok := d.Content.(int64); ok && d.Number == 1 {
			r.CompletionDate = time.Unix(n, 0).UTC().Format(sfrDate)
		}
	}
	r.Scope, _ = sfrMap.at(3).(int64)
	ids, _ := sfrMap.at(4).([]any)
	for _, id := range ids {
		fw := asCmap(id)
		if fw.at(3) != nil {
			r.Manifest = true
		}
		ds, _ := fw.at(1).([]any)
		for _, d := range ds {
			dl, _ := d.([]any)
			digests = append(digests, dl)
		}
	}
	// With a source manifest, the digests cover the manifest, not an image.
	if !r.Manifest {
		for _, d := range digests {
			if len(d) != 2 {
				return nil, errors.New("malformed digest")
			}
			id, _ := d[0].(int64)
			alg, known := sfrHashAlg[id]
			value, _ := d[1].([]byte)
			if !known {
				return nil, fmt.Errorf("unsupported digest algorithm %v", d[0])
			}
			if len(value) != digestSize[alg] {
				return nil, fmt.Errorf("not a %s digest", alg)
			}
			h := hex.EncodeToString(value)
			if !slices.Contains(r.Digests[alg], h) {
				r.Digests[alg] = append(r.Digests[alg], h)
			}
		}
	}
	issues, _ := sfrMap.at(5).([]any)
	for _, i := range issues {
		is := asCmap(i)
		a := asCmap(is.at(2))
		str := func(m cmap, k int64) string { s, _ := m.at(k).(string); return s }
		r.Issues = append(r.Issues, SFRIssue{
			Title: str(is, 0), Description: str(is, 1), CVSSScore: str(a, 0), CVSSVector: str(a, 1),
			CWE: str(is, 3), CVE: str(is, 4),
		})
	}
	return r, nil
}

// measurementMaps returns the measurement maps of an [environment, [measurement-map...]] record.
func measurementMaps(record any) []any {
	pair, _ := record.([]any)
	if len(pair) != 2 {
		return nil
	}
	ms, _ := pair[1].([]any)
	return ms
}

// kidString shows a kid as text when it is printable, else as hex.
func kidString(kid []byte) string {
	for _, c := range kid {
		if c < 0x20 || c > 0x7e {
			return hex.EncodeToString(kid)
		}
	}
	return string(kid)
}

var jwsHash = map[string]struct {
	curve elliptic.Curve
	hash  crypto.Hash
}{
	"ES256": {elliptic.P256(), crypto.SHA256},
	"ES384": {elliptic.P384(), crypto.SHA384},
	"ES512": {elliptic.P521(), crypto.SHA512},
}

// Verify checks the report's signature with pub.
func (r *SFR) Verify(pub *ecdsa.PublicKey) error {
	if r.Format == SFRFormatCoRIM {
		alg, err := r.cose.Headers.Protected.Algorithm()
		if err != nil {
			return err
		}
		v, err := cose.NewVerifier(alg, pub)
		if err != nil {
			return err
		}
		return r.cose.Verify(nil, v)
	}
	h, ok := jwsHash[r.alg]
	if !ok {
		return fmt.Errorf("JWS algorithm %q is not supported", r.alg)
	}
	if pub.Curve != h.curve {
		return fmt.Errorf("%s needs a %s key", r.alg, h.curve.Params().Name)
	}
	size := (h.curve.Params().BitSize + 7) / 8
	if len(r.sig) != 2*size {
		return errors.New("JWS signature has the wrong length")
	}
	d := h.hash.New()
	d.Write(r.input)
	rr, ss := new(big.Int).SetBytes(r.sig[:size]), new(big.Int).SetBytes(r.sig[size:])
	if !ecdsa.Verify(pub, d.Sum(nil), rr, ss) {
		return errors.New("signature does not verify")
	}
	return nil
}

// AcceptSFR applies the spec's three checks to one report for one image,
// whose provenance subject is image, under policy firmware.review. It
// returns the review provider role whose key verified the report.
func AcceptSFR(r *SFR, image Obj, trust *TrustRoot, review Obj) (string, error) {
	// 1. Signed with a key of a review provider the policy allows.
	role := ""
	for _, p := range Strs(review, "providers") {
		for _, k := range trust.Roles[p] {
			if role == "" && r.Verify(k.Public) == nil {
				role = p
			}
		}
	}
	if role == "" {
		return "", failf("signature does not verify with a key of any review provider the policy allows")
	}
	// 2. Names the image's digest, under an algorithm the provenance also uses.
	if err := sfrNamesImage(r, image); err != nil {
		return "", err
	}
	// 3. Scope and open issues meet the policy.
	if vs := Strs(review, "frameworkVersions"); len(vs) > 0 && !slices.Contains(vs, r.FrameworkVersion) {
		return "", failf("review framework version %q is not one the policy accepts", r.FrameworkVersion)
	}
	minScope, _ := Int(review, "minScope")
	if r.Scope < 1 {
		return "", failf("states no review scope (framework %s)", r.FrameworkVersion)
	}
	if r.Scope < minScope {
		return "", failf("review scope %d is below the policy's minimum of %d", r.Scope, minScope)
	}
	limit, err := maxOpenCVSS(review)
	if err != nil {
		return "", err
	}
	for _, is := range r.Issues {
		score, err := strconv.ParseFloat(strings.TrimSpace(is.CVSSScore), 64)
		if err != nil {
			return "", failf("open issue %q has no CVSS score", is.Title)
		}
		if score > limit {
			return "", failf("open issue %q scores CVSS %s, above the policy's %s", is.Title, is.CVSSScore, num(limit))
		}
	}
	return role, nil
}

// sfrNamesImage is check 2: the report names a digest of the image, and the
// provenance lists the image's digest in every algorithm the report uses,
// each of which the report names.
func sfrNamesImage(r *SFR, image Obj) error {
	if len(r.Digests) == 0 {
		if r.Manifest {
			return failf("its digests cover a source manifest, not a firmware image")
		}
		return failf("names no firmware digest")
	}
	for _, alg := range sortedKeys(r.Digests) {
		want := S(image, "digest", alg)
		if want == "" {
			return failf("uses %s, which the image's provenance does not list", alg)
		}
		if !slices.Contains(r.Digests[alg], want) {
			return failf("names no %s digest of this image", alg)
		}
	}
	return nil
}

func maxOpenCVSS(review Obj) (float64, error) {
	switch v := get(review, "maxOpenIssueCVSS").(type) {
	case float64:
		return v, nil
	case json.Number:
		return v.Float64()
	case int64:
		return float64(v), nil
	}
	if n, ok := Int(review, "maxOpenIssueCVSS"); ok {
		return float64(n), nil
	}
	return 0, failf("policy firmware.review: maxOpenIssueCVSS must give the highest CVSS score an open issue may have")
}

// ReviewImage is one image the review check covers: its HBOM name and provenance subject.
type ReviewImage struct {
	Name    string
	Subject Obj
}

// ReviewResult is what the review check vouches for.
type ReviewResult struct {
	Accepted  map[string][]string // image name -> report files accepted for it
	Providers []string            // the providers that signed them
	Inputs    []Obj               // every accepted report, by digest
}

// ReviewCheck finds, for each image the policy's firmware.review.images
// names, a report in the bundle's review directory that AcceptSFR accepts.
func ReviewCheck(bundle string, trust *TrustRoot, policy Obj, images []ReviewImage) (*ReviewResult, error) {
	review := O(policy, "firmware", "review")
	if len(Strs(review, "providers")) == 0 {
		return nil, failf("policy firmware.review lists no review provider")
	}
	if _, err := maxOpenCVSS(review); err != nil {
		return nil, err
	}
	byName := map[string]Obj{}
	for _, im := range images {
		byName[im.Name] = im.Subject
	}
	required := Strs(review, "images")
	if len(required) == 0 {
		return nil, failf("policy firmware.review names no image")
	}
	dir := filepath.Join(bundle, ReviewDir)
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	type report struct {
		file string
		sfr  *SFR
	}
	var reports []report
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		file := ReviewDir + "/" + e.Name()
		r, err := ReadSFR(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, failf("firmware review: %s: not a signed S.A.F.E. report: %v", file, err)
		}
		reports = append(reports, report{file, r})
	}
	res := &ReviewResult{Accepted: map[string][]string{}}
	used := map[string]bool{}
	for _, name := range required {
		subject := byName[name]
		if subject == nil {
			return nil, failf("policy firmware.review names %s, which is not an image of this release", name)
		}
		var reasons []string
		for _, rep := range reports {
			if sfrNamesImage(rep.sfr, subject) != nil {
				continue
			}
			if _, err := AcceptSFR(rep.sfr, subject, trust, review); err != nil {
				reasons = append(reasons, rep.file+": "+err.Error())
				continue
			}
			res.Accepted[name] = append(res.Accepted[name], rep.file)
			used[rep.file] = true
			if !slices.Contains(res.Providers, rep.sfr.Provider) {
				res.Providers = append(res.Providers, rep.sfr.Provider)
			}
		}
		if len(res.Accepted[name]) == 0 {
			if len(reasons) == 0 {
				reasons = []string{"no report names its digest"}
			}
			return nil, failf("firmware review: no accepted S.A.F.E. report for %s (%s)", name, strings.Join(reasons, "; "))
		}
	}
	files := sortedKeys(used)
	for _, f := range files {
		in, err := fileRD(filepath.Join(bundle, f), f)
		if err != nil {
			return nil, err
		}
		res.Inputs = append(res.Inputs, in)
	}
	return res, nil
}

// trackClaim is the highest level of track (DESIGN, FIRMWARE, ...) the policy's claims name.
func trackClaim(policy Obj, track string) int {
	level := 0
	for _, list := range O(policy, "claims") {
		for _, c := range Strs(Obj{"v": list}, "v") {
			var n int
			if _, err := fmt.Sscanf(c, "HSLSA_"+track+"_LEVEL_%d", &n); err == nil && n > level {
				level = n
			}
		}
	}
	return level
}

// requireFirmwareL3Rules refuses a Firmware L3 claim. The review check runs
// whenever the policy configures it, but L3 also needs SLSA Build L3 and
// releases in a transparency log, which this tool does not check yet.
func requireFirmwareL3Rules(policy Obj, images []ReviewImage) error {
	level := trackClaim(policy, "FIRMWARE")
	if level < 3 {
		return nil
	}
	required := Strs(policy, "firmware", "review", "images")
	for _, im := range images {
		if !slices.Contains(required, im.Name) {
			return failf("policy claims Firmware L%d but does not require a S.A.F.E. review of %s", level, im.Name)
		}
	}
	return failf("policy claims Firmware L%d, but the reference tool does not yet check SLSA Build L3 or transparency log inclusion", level)
}

// Producing reports

// SignSFR signs a JSON short-form report in the given form with signer.
func SignSFR(report Obj, signer *Signer, format string) ([]byte, error) {
	if _, err := sfrFromJSON(report); err != nil {
		return nil, err
	}
	switch format {
	case SFRFormatJWS:
		return signSFRJWS(report, signer)
	case SFRFormatCoRIM:
		return signSFRCoRIM(report, signer)
	}
	return nil, fmt.Errorf("unknown report form %q (jws or corim)", format)
}

func jwsAlg(pub *ecdsa.PublicKey) (string, crypto.Hash, error) {
	for name, h := range jwsHash {
		if h.curve == pub.Curve {
			return name, h.hash, nil
		}
	}
	return "", 0, fmt.Errorf("unsupported curve %s", pub.Curve.Params().Name)
}

func signSFRJWS(report Obj, signer *Signer) ([]byte, error) {
	alg, h, err := jwsAlg(&signer.priv.PublicKey)
	if err != nil {
		return nil, err
	}
	hdr, err := json.Marshal(map[string]string{"alg": alg, "kid": signer.Key.ID, "typ": "JWT"})
	if err != nil {
		return nil, err
	}
	input := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(compactJSON(report))
	var sum []byte
	switch h {
	case crypto.SHA256:
		s := sha256.Sum256([]byte(input))
		sum = s[:]
	case crypto.SHA384:
		s := sha512.Sum384([]byte(input))
		sum = s[:]
	default:
		s := sha512.Sum512([]byte(input))
		sum = s[:]
	}
	rr, ss, err := ecdsa.Sign(rand.Reader, signer.priv, sum)
	if err != nil {
		return nil, err
	}
	size := (signer.priv.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	rr.FillBytes(sig[:size])
	ss.FillBytes(sig[size:])
	return []byte(input + "." + base64.RawURLEncoding.EncodeToString(sig) + "\n"), nil
}

// sfrCoRIM converts a JSON report to the S.A.F.E. CoRIM profile, laid out as OcpReportLib lays it out.
func sfrCoRIM(report Obj, id string) (any, error) {
	date, err := time.Parse(sfrDate, S(report, "audit", "completion_date"))
	if err != nil {
		return nil, fmt.Errorf("completion_date: %w", err)
	}
	scope, err := scopeNumber(get(report, "audit", "scope_number"))
	if err != nil {
		return nil, err
	}
	if Has(O(report, "device"), "manifest") {
		return nil, errors.New("reports over a source manifest are not supported")
	}
	var digests [][]any
	for _, d := range []struct {
		alg   int64
		field string
	}{{-43, "fw_hash_sha2_384"}, {-44, "fw_hash_sha2_512"}} {
		if h := S(report, "device", d.field); h != "" {
			b, err := hex.DecodeString(h)
			if err != nil {
				return nil, fmt.Errorf("device.%s: %w", d.field, err)
			}
			digests = append(digests, []any{d.alg, b})
		}
	}
	fwID := map[int64]any{}
	if v := S(report, "device", "fw_version"); v != "" {
		fwID[0] = map[int64]any{0: v}
	}
	if len(digests) > 0 {
		fwID[1] = digests
	}
	if v := S(report, "device", "repo_tag"); v != "" {
		fwID[2] = v
	}
	sfr := map[int64]any{
		0: S(report, "review_framework_version"),
		1: S(report, "audit", "report_version"),
		2: cbor.Tag{Number: 1, Content: date.Unix()},
		3: scope,
		4: []any{fwID},
	}
	var issues []any
	for _, is := range Objs(report, "audit", "issues") {
		cvss := map[int64]any{0: S(is, "cvss_score"), 1: S(is, "cvss_vector")}
		if v := S(report, "audit", "cvss_version"); v != "" {
			cvss[2] = v
		}
		entry := map[int64]any{0: S(is, "title"), 1: S(is, "description"), 2: cvss}
		if v := S(is, "cwe"); v != "" {
			entry[3] = v
		}
		if v := S(is, "cve"); v != "" {
			entry[4] = v
		}
		issues = append(issues, entry)
	}
	if len(issues) > 0 {
		sfr[5] = issues
	}
	if v := S(report, "audit", "solid_ver"); v != "" {
		sfr[6] = v
	}
	class := map[int64]any{}
	if v := S(report, "device", "vendor"); v != "" {
		class[1] = v
	}
	if v := S(report, "device", "product"); v != "" {
		class[2] = v
	}
	env := map[int64]any{0: class}
	comid := map[int64]any{
		1: map[int64]any{0: id + "-comid"},
		4: map[int64]any{10: []any{[]any{
			[]any{[]any{env, []any{map[int64]any{1: map[int64]any{2: digests}}}}},
			[]any{[]any{env, []any{map[int64]any{1: map[int64]any{-1: sfr}}}}},
		}}},
	}
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	comidBytes, err := em.Marshal(comid)
	if err != nil {
		return nil, err
	}
	return cbor.Tag{Number: 501, Content: map[int64]any{
		0: id,
		1: []any{cbor.Tag{Number: 506, Content: comidBytes}},
		3: cbor.Tag{Number: 111, Content: sfrProfileOID},
		5: []any{map[int64]any{0: S(report, "audit", "srp"), 2: []any{1}}},
	}}, nil
}

func signSFRCoRIM(report Obj, signer *Signer) ([]byte, error) {
	id := "sfr-" + strings.ToLower(strings.ReplaceAll(S(report, "device", "product")+"-"+S(report, "device", "fw_version"), " ", "-"))
	c, err := sfrCoRIM(report, id)
	if err != nil {
		return nil, err
	}
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	payload, err := em.Marshal(c)
	if err != nil {
		return nil, err
	}
	alg, err := coseAlg(&signer.priv.PublicKey)
	if err != nil {
		return nil, err
	}
	cs, err := cose.NewSigner(alg, signer.priv)
	if err != nil {
		return nil, err
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(alg)
	msg.Headers.Unprotected[cose.HeaderLabelKeyID] = []byte(signer.Key.ID)
	msg.Payload = payload
	if err := msg.Sign(rand.Reader, nil, cs); err != nil {
		return nil, err
	}
	return msg.MarshalCBOR()
}

func sha512Hex(data []byte) string {
	sum := sha512.Sum512(data)
	return hex.EncodeToString(sum[:])
}

// Describe is a few lines on a report, for hslsa safe show.
func (r *SFR) Describe() []string {
	var digests []string
	for _, alg := range sortedKeys(r.Digests) {
		for _, d := range r.Digests[alg] {
			digests = append(digests, alg+":"+d)
		}
	}
	if len(digests) == 0 {
		digests = []string{"none"}
		if r.Manifest {
			digests = []string{"none (covers a source manifest)"}
		}
	}
	out := []string{
		"form:      " + r.Format + ", kid " + strconv.Quote(r.KeyID),
		"provider:  " + r.Provider,
		fmt.Sprintf("review:    framework %s, report %s, scope %d, completed %s", r.FrameworkVersion, r.ReportVersion, r.Scope, r.CompletionDate),
		"firmware:  " + strings.Join(digests, ", "),
		fmt.Sprintf("issues:    %d open", len(r.Issues)),
	}
	issues := slices.Clone(r.Issues)
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].CVSSScore > issues[j].CVSSScore })
	for _, is := range issues {
		out = append(out, fmt.Sprintf("  CVSS %s  %s", is.CVSSScore, is.Title))
	}
	return out
}

// The Caliptra example's simulated review

// SimulatedProvider names the review provider of the Caliptra example. No
// review took place: the reports exist to exercise the verifier's checks.
const SimulatedProvider = "SIMULATED review provider (not an OCP S.A.F.E. approved provider; no review took place)"

// CaliptraReview signs one simulated S.A.F.E. report for each Caliptra image
// with provenance in the bundle: the ROM's as a JWS, the FMC's and the
// runtime's as CoRIM, so the example exercises both forms.
func CaliptraReview(bundle, lockPath, key string) error {
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	rom, err := DecodeEnvelope(filepath.Join(bundle, "att", FWAtt["rom"]))
	if err != nil {
		return err
	}
	fw, err := DecodeEnvelope(filepath.Join(bundle, "att", FWAtt["bundle"]))
	if err != nil {
		return err
	}
	subjects := map[string]Obj{"caliptra-rom": firstSubject(rom)}
	for _, s := range Objs(fw, "subject") {
		switch S(s, "name") {
		case Images["fmc"]:
			subjects["caliptra-fmc"] = s
		case Images["runtime"]:
			subjects["caliptra-runtime"] = s
		}
	}
	dir := filepath.Join(bundle, ReviewDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tag := S(lock, "caliptraSw", "tag")
	for _, name := range []string{"caliptra-rom", "caliptra-fmc", "caliptra-runtime"} {
		s := subjects[name]
		if S(s, "digest", "sha384") == "" {
			return fmt.Errorf("firmware provenance has no sha384 digest for %s", name)
		}
		report := Obj{
			"review_framework_version": "1.1",
			"device": Obj{
				"vendor": "CHIPS Alliance", "product": "Caliptra", "category": "SIMULATED review of " + S(s, "name"),
				"repo_tag":   S(lock, "caliptraSw", "repo") + "/tree/" + S(lock, "caliptraSw", "commit"),
				"fw_version": tag, "fw_hash_sha2_384": S(s, "digest", "sha384"), "fw_hash_sha2_512": "",
			},
			"audit": Obj{
				"srp": SimulatedProvider, "methodology": "none (simulated)",
				"completion_date": time.Now().UTC().Format(sfrDate), "report_version": "1.0",
				"scope_number": int64(1), "cvss_version": "3.1",
				"issues": []any{Obj{
					"title":       "SIMULATED low-severity issue",
					"cvss_score":  "1.6",
					"cvss_vector": "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
					"cwe":         "CWE-1188",
					"description": "Not a finding. It exercises the verifier's check of open issues against policy.",
					"cve":         nil,
				}},
			},
		}
		format, ext := SFRFormatCoRIM, ".sfr.cose"
		if name == "caliptra-rom" {
			format, ext = SFRFormatJWS, ".sfr.jws"
		}
		data, err := SignSFR(report, signer, format)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name+ext), data, 0o644); err != nil {
			return err
		}
		fmt.Printf("review: signed a simulated S.A.F.E. report (%s) for %s sha384:%s\n", format, name, S(s, "digest", "sha384"))
	}
	return nil
}
