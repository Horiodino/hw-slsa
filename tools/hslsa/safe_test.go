package hslsa

// S.A.F.E. short-form reports and the Firmware L3 review checks, without a
// produced bundle. testdata/safe holds reports this project did not write:
// two that review providers published for Caliptra, and one report in each
// form signed by OCP's own OcpReportLib (see testdata/safe/README.md).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const safeData = "testdata/safe"

func safeKey(t *testing.T, name string) Key {
	t.Helper()
	return ok(PublicKeyFromPEM(string(ok(os.ReadFile(filepath.Join(safeData, name))))))
}

func readSafe(t *testing.T, name string) *SFR {
	t.Helper()
	return ok(ReadSFR(filepath.Join(safeData, name)))
}

// fixtureImage is the provenance subject of the image the OcpReportLib reports name.
func fixtureImage(t *testing.T) Obj {
	t.Helper()
	data := ok(os.ReadFile(filepath.Join(safeData, "fixture-image.bin")))
	return Obj{"name": "fixture-image.bin", "digest": Obj{"sha256": sha256Bytes(data), "sha384": sha384Bytes(data), "sha512": sha512Hex(data)}}
}

func reviewPolicy(providers ...string) Obj {
	return Obj{"providers": toAny(providers), "minScope": int64(1), "maxOpenIssueCVSS": 6.9}
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func trustWith(role string, keys ...Key) *TrustRoot {
	return &TrustRoot{Roles: map[string][]Key{role: keys}}
}

// Reports review providers published

func TestPublishedCaliptraReportVerifies(t *testing.T) {
	// NCC Group's 2023 report on the Caliptra FMC, as published in OCP-Security-SAFE.
	r := readSafe(t, "caliptra-fmc-2023-ncc.jws")
	must(t, r.Verify(safeKey(t, "ncc-group.pub.pem").Public))
	if r.Format != SFRFormatJWS || r.Provider != "NCC Group" || r.CompletionDate != "2023-10-13" || len(r.Issues) != 0 {
		t.Fatalf("read %+v", r)
	}
	want := "1797be80a931b1a5d6e057100eeb393c268c23e7465f59ae5eec5bd20a164e9497ec029e1d0acfa4a995575f8dfe5a6a"
	if len(r.Digests["sha384"]) != 1 || r.Digests["sha384"][0] != want || len(r.Digests["sha512"]) != 1 {
		t.Fatalf("digests %v", r.Digests)
	}
	if r.Verify(safeKey(t, "ioactive.pub.pem").Public) == nil {
		t.Fatal("NCC Group's report verified with IOActive's key")
	}
}

func TestPublishedReportIsNotForThisBuild(t *testing.T) {
	// The 2023 report names the FMC ELF of release_v20231014_0. It is genuine,
	// but it cannot count for the FMC this example builds from fw-2.1.3.
	r := readSafe(t, "caliptra-fmc-2023-ncc.jws")
	trust := trustWith("ncc-group", safeKey(t, "ncc-group.pub.pem"))
	image := Obj{"digest": Obj{"sha384": fmcDigest, "sha512": strings.Repeat("00", 64)}}
	_, err := AcceptSFR(r, image, trust, reviewPolicy("ncc-group"))
	rejects(t, err, "names no sha384 digest of this image")
	// The same report, for an image whose provenance has only sha256 and sha384.
	image = Obj{"digest": Obj{"sha256": strings.Repeat("00", 32), "sha384": r.Digests["sha384"][0]}}
	_, err = AcceptSFR(r, image, trust, reviewPolicy("ncc-group"))
	rejects(t, err, "uses sha512, which the image's provenance does not list")
	// Even for the image it names, it predates scope numbers (framework 0.3), so no policy can accept it.
	image = Obj{"digest": Obj{"sha384": r.Digests["sha384"][0], "sha512": r.Digests["sha512"][0]}}
	_, err = AcceptSFR(r, image, trust, reviewPolicy("ncc-group"))
	rejects(t, err, "states no review scope (framework 0.3)")
}

func TestPublishedReportWithoutDigest(t *testing.T) {
	// IOActive's 2024 report on Caliptra firmware names repository commits and pull requests, not an image digest.
	r := readSafe(t, "caliptra-fw-2024-ioactive.jws")
	must(t, r.Verify(safeKey(t, "ioactive.pub.pem").Public))
	if r.Scope != 1 || r.Provider != "IOActive, Incorporated" {
		t.Fatalf("read %+v", r)
	}
	trust := trustWith("ioactive", safeKey(t, "ioactive.pub.pem"))
	_, err := AcceptSFR(r, Obj{"digest": Obj{"sha384": fmcDigest}}, trust, reviewPolicy("ioactive"))
	rejects(t, err, "names no firmware digest")
}

// Reports OCP's library signed

func TestOcpReportLibReportsVerify(t *testing.T) {
	trust := trustWith("fixture-provider", safeKey(t, "ocpreportlib-fixture.pub.pem"))
	image := fixtureImage(t)
	for _, name := range []string{"ocpreportlib.sfr.jws", "ocpreportlib.sfr.cose"} {
		r := readSafe(t, name)
		if r.Provider != "OcpReportLib fixture (not a real review provider)" || r.CompletionDate != "2026-10-01" ||
			r.Scope != 2 || r.FrameworkVersion != "1.1" || r.ReportVersion != "1.0" || r.KeyID != "hslsa-fixture" {
			t.Fatalf("%s: read %+v", name, r)
		}
		if len(r.Issues) != 1 || r.Issues[0].CVSSScore != "4.3" || r.Issues[0].CWE != "CWE-200" {
			t.Fatalf("%s: issues %+v", name, r.Issues)
		}
		if got := ok(AcceptSFR(r, image, trust, reviewPolicy("fixture-provider"))); got != "fixture-provider" {
			t.Fatalf("%s: accepted by %q", name, got)
		}
	}
	if want := []string{"form:      corim, kid \"hslsa-fixture\""}; readSafe(t, "ocpreportlib.sfr.cose").Describe()[0] != want[0] {
		t.Fatalf("describe: %v", readSafe(t, "ocpreportlib.sfr.cose").Describe())
	}
}

func TestOcpReportLibCoRIMAltered(t *testing.T) {
	data := ok(os.ReadFile(filepath.Join(safeData, "ocpreportlib.sfr.cose")))
	i := strings.Index(string(data), "Fixture issue")
	data[i] = 'f'
	r := ok(ParseSFR(data))
	if r.Verify(safeKey(t, "ocpreportlib-fixture.pub.pem").Public) == nil {
		t.Fatal("an altered CoRIM report verified")
	}
}

// The three checks, on reports this tool signs

func signedReport(t *testing.T, signer *Signer, format string, edit func(Obj)) *SFR {
	t.Helper()
	img := fixtureImage(t)
	rep := Obj{
		"review_framework_version": "1.1",
		"device": Obj{"vendor": "HSLSA test vendor", "product": "fixture image", "category": "test", "repo_tag": "fixture-v1",
			"fw_version": "1.0.0", "fw_hash_sha2_384": S(img, "digest", "sha384"), "fw_hash_sha2_512": ""},
		"audit": Obj{"srp": "Test provider", "methodology": "none", "completion_date": "2026-10-01", "report_version": "1.0",
			"scope_number": int64(1), "cvss_version": "3.1", "issues": []any{
				Obj{"title": "Low issue", "cvss_score": "3.1", "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N", "cwe": "CWE-20", "description": "test", "cve": nil},
			}},
	}
	if edit != nil {
		edit(rep)
	}
	data := ok(SignSFR(rep, signer, format))
	return ok(ParseSFR(data))
}

func TestSignedReportsRoundTrip(t *testing.T) {
	signer := ok(Keygen(t.TempDir(), "review-provider"))
	trust := trustWith("review-provider", signer.Key)
	for _, format := range []string{SFRFormatJWS, SFRFormatCoRIM} {
		r := signedReport(t, signer, format, nil)
		if r.Format != format || r.KeyID != signer.Key.ID || r.Provider != "Test provider" || r.CompletionDate != "2026-10-01" ||
			r.Scope != 1 || len(r.Issues) != 1 || r.Issues[0].Title != "Low issue" || len(r.Digests) != 1 {
			t.Fatalf("%s: read %+v", format, r)
		}
		if got := ok(AcceptSFR(r, fixtureImage(t), trust, reviewPolicy("review-provider"))); got != "review-provider" {
			t.Fatalf("%s: accepted by %q", format, got)
		}
	}
}

func TestReviewChecks(t *testing.T) {
	signer := ok(Keygen(t.TempDir(), "review-provider"))
	attacker := ok(Keygen(t.TempDir(), "attacker"))
	trust := &TrustRoot{Roles: map[string][]Key{"review-provider": {signer.Key}, "attacker": {attacker.Key}}}
	image := fixtureImage(t)
	cases := []struct {
		name   string
		signer *Signer
		policy Obj
		edit   func(Obj)
		reason string
	}{
		{"signed by a key the policy does not list", attacker, nil, nil,
			"signature does not verify with a key of any review provider the policy allows"},
		{"for another image", signer, nil, func(r Obj) { O(r, "device")["fw_hash_sha2_384"] = fmcDigest },
			"names no sha384 digest of this image"},
		{"digest over a source manifest", signer, nil, func(r Obj) {
			O(r, "device")["manifest"] = []any{Obj{"file_name": "a.c", "file_hash": strings.Repeat("ab", 64)}}
		}, "its digests cover a source manifest, not a firmware image"},
		{"scope below the policy's", signer, Obj{"providers": []any{"review-provider"}, "minScope": int64(2), "maxOpenIssueCVSS": 6.9}, nil,
			"review scope 1 is below the policy's minimum of 2"},
		{"open issue above the policy's severity", signer, nil, func(r Obj) {
			O(r, "audit")["issues"] = []any{Obj{"title": "Stack overflow in mailbox", "cvss_score": "8.1", "cvss_vector": "x", "cwe": "CWE-121", "description": "d"}}
		}, `open issue "Stack overflow in mailbox" scores CVSS 8.1, above the policy's 6.9`},
		{"open issue without a score", signer, nil, func(r Obj) {
			O(r, "audit")["issues"] = []any{Obj{"title": "Unscored", "cvss_score": "", "cvss_vector": "", "cwe": "", "description": "d"}}
		}, `open issue "Unscored" has no CVSS score`},
		{"framework version the policy does not accept", signer,
			Obj{"providers": []any{"review-provider"}, "maxOpenIssueCVSS": 6.9, "frameworkVersions": []any{"2.0"}}, nil,
			`review framework version "1.1" is not one the policy accepts`},
	}
	for _, c := range cases {
		for _, format := range []string{SFRFormatJWS, SFRFormatCoRIM} {
			if c.name == "digest over a source manifest" && format == SFRFormatCoRIM {
				continue // this tool does not sign CoRIM reports over a manifest
			}
			t.Run(c.name+"/"+format, func(t *testing.T) {
				policy := c.policy
				if policy == nil {
					policy = reviewPolicy("review-provider")
				}
				_, err := AcceptSFR(signedReport(t, c.signer, format, c.edit), image, trust, policy)
				rejects(t, err, c.reason)
			})
		}
	}
}

func TestJWSPayloadAltered(t *testing.T) {
	signer := ok(Keygen(t.TempDir(), "review-provider"))
	img := fixtureImage(t)
	rep := Obj{"review_framework_version": "1.1", "device": Obj{"fw_hash_sha2_384": S(img, "digest", "sha384")},
		"audit": Obj{"srp": "p", "completion_date": "2026-10-01", "scope_number": int64(1), "issues": []any{}}}
	data := string(ok(SignSFR(rep, signer, SFRFormatJWS)))
	parts := strings.Split(strings.TrimSpace(data), ".")
	O(rep, "audit")["scope_number"] = int64(3)
	parts[1] = strings.Split(string(ok(SignSFR(rep, signer, SFRFormatJWS))), ".")[1]
	r := ok(ParseSFR([]byte(strings.Join(parts, "."))))
	if r.Verify(signer.Key.Public) == nil {
		t.Fatal("a JWS with its payload swapped verified")
	}
}

func TestReviewCheckFindsReportPerImage(t *testing.T) {
	signer := ok(Keygen(t.TempDir(), "review-provider"))
	trust := trustWith("review-provider", signer.Key)
	bundle := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(bundle, ReviewDir), 0o755))
	img := fixtureImage(t)
	rep := Obj{"review_framework_version": "1.1", "device": Obj{"product": "fixture", "fw_hash_sha2_384": S(img, "digest", "sha384")},
		"audit": Obj{"srp": "p", "completion_date": "2026-10-01", "scope_number": int64(1), "issues": []any{}}}
	must(t, os.WriteFile(filepath.Join(bundle, ReviewDir, "fixture.sfr.cose"), ok(SignSFR(rep, signer, SFRFormatCoRIM)), 0o644))
	other := Obj{"name": "other.bin", "digest": Obj{"sha384": fmcDigest}}
	images := []ReviewImage{{"fixture", img}, {"other", other}}
	review := reviewPolicy("review-provider")
	policy := Obj{"firmware": Obj{"review": review}}

	review["images"] = []any{"fixture"}
	res := ok(ReviewCheck(bundle, trust, policy, images))
	if len(res.Accepted["fixture"]) != 1 || len(res.Inputs) != 1 || S(res.Inputs[0], "name") != "review/fixture.sfr.cose" {
		t.Fatalf("result %+v", res)
	}

	review["images"] = []any{"fixture", "other"}
	_, err := ReviewCheck(bundle, trust, policy, images)
	rejects(t, err, "firmware review: no accepted S.A.F.E. report for other (no report names its digest)")

	review["images"] = []any{"fixture", "caliptra-mcu"}
	_, err = ReviewCheck(bundle, trust, policy, images)
	rejects(t, err, "policy firmware.review names caliptra-mcu, which is not an image of this release")

	review["images"] = []any{"fixture"}
	delete(review, "maxOpenIssueCVSS")
	_, err = ReviewCheck(bundle, trust, policy, images)
	rejects(t, err, "policy firmware.review: maxOpenIssueCVSS must give")

	review["maxOpenIssueCVSS"] = 6.9
	must(t, os.WriteFile(filepath.Join(bundle, ReviewDir, "notes.txt"), []byte("not a report"), 0o644))
	_, err = ReviewCheck(bundle, trust, policy, images)
	rejects(t, err, "firmware review: review/notes.txt: not a signed S.A.F.E. report")
}
