package hslsa

// CoRIM reference values and their appraisal, without a produced bundle.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	sha256OID = "2.16.840.1.101.3.4.2.1"
	fmcDigest = "872f80f6add2261a9368f3a8e71d50bd64db6be4a72bea194e78300c4e6d885959ce15844ce9c9665c0327ce29f12533"
	rtDigest  = "e466854dbfe3984070d38b587803c3385ad2698e45518dfd247809b0e96809c305b46c54c7bac0bc1ab6bf80f2b52c69"
)

func writeTestCoRIM(t *testing.T, refs []RefValue) (path string, keys []Key) {
	t.Helper()
	dir := t.TempDir()
	signer := ok(Keygen(dir, "firmware-platform"))
	path = filepath.Join(dir, "fw.corim")
	must(t, WriteCoRIM(path, "test-fw", "test platform", "firmware-platform", refs, signer))
	return path, []Key{signer.Key}
}

func TestCoRIMRoundTrip(t *testing.T) {
	layer := uint64(1)
	refs := append(CaliptraRefValues(fmcDigest, rtDigest, 1),
		RefValue{Env: DiceEnv{Vendor: "ACME", Model: "widget", Layer: &layer}, Digests: []FWID{{sha256OID, strings.Repeat("ab", 32)}, {SHA384OID, fmcDigest}}})
	path, keys := writeTestCoRIM(t, refs)
	c, err := OpenCoRIM(path, keys, "corim")
	must(t, err)
	if c.ID != "test-fw" || c.Profile != CoRIMProfile || c.Signer != "firmware-platform" {
		t.Fatalf("got id %q, profile %q, signer %q", c.ID, c.Profile, c.Signer)
	}
	if !sameRefValues(c.RefValues, refs) {
		t.Fatalf("reference values changed in the round trip:\n got %v\nwant %v", c.RefValues, refs)
	}
	if *c.RefValues[0].SVN != 0x101 {
		t.Fatalf("Caliptra SVN 1 should read 0x101 as the device reports it, got %#x", *c.RefValues[0].SVN)
	}
}

func TestCoRIMSignedByAnotherKey(t *testing.T) {
	path, _ := writeTestCoRIM(t, CaliptraRefValues(fmcDigest, rtDigest, 1))
	other := ok(Keygen(t.TempDir(), "firmware-platform"))
	_, err := OpenCoRIM(path, []Key{other.Key}, "firmware CoRIM")
	rejects(t, err, "firmware CoRIM: signature does not verify with any allowed key")
}

func TestCoRIMPayloadAltered(t *testing.T) {
	path, keys := writeTestCoRIM(t, CaliptraRefValues(fmcDigest, rtDigest, 1))
	data := ok(os.ReadFile(path))
	i := strings.Index(string(data), "CALIPTRA_2_X_RT")
	data[i] = 'X'
	must(t, os.WriteFile(path, data, 0o644))
	_, err := OpenCoRIM(path, keys, "firmware CoRIM")
	rejects(t, err, "firmware CoRIM: signature does not verify")
}

func TestCoRIMNotCBOR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.corim")
	must(t, os.WriteFile(path, []byte("{}"), 0o644))
	_, err := OpenCoRIM(path, nil, "firmware CoRIM")
	rejects(t, err, "firmware CoRIM: not a valid signed CoRIM")
}

func TestAppraise(t *testing.T) {
	refs := CaliptraRefValues(fmcDigest, rtDigest, 1)
	fmc := TcbInfo{Type: FMCTcbType, SVN: 0x101, HasSVN: true, FWIDs: []FWID{{SHA384OID, fmcDigest}}}
	for _, c := range []struct {
		name        string
		tcb         func(TcbInfo) TcbInfo
		named, pass bool
	}{
		{"the measured FMC", func(t TcbInfo) TcbInfo { return t }, true, true},
		{"another FMC", func(t TcbInfo) TcbInfo { t.FWIDs = []FWID{{SHA384OID, rtDigest}}; return t }, true, false},
		{"the FMC with another SVN", func(t TcbInfo) TcbInfo { t.SVN = 0x102; return t }, true, false},
		{"the FMC with no SVN", func(t TcbInfo) TcbInfo { t.HasSVN = false; return t }, true, false},
		{"the FMC digest under a hash the CoRIM lacks", func(t TcbInfo) TcbInfo { t.FWIDs = []FWID{{sha256OID, strings.Repeat("ab", 32)}}; return t }, true, false},
		{"the FMC plus a second FWID under the same hash", func(t TcbInfo) TcbInfo {
			t.FWIDs = append(t.FWIDs, FWID{SHA384OID, rtDigest})
			return t
		}, true, false},
		{"the FMC digest reported for the runtime layer", func(t TcbInfo) TcbInfo { t.Type = RTTcbType; return t }, true, false},
		{"a layer with no reference value", func(t TcbInfo) TcbInfo { t.Type = "CALIPTRA_2_X_FUSE_OWNER_INFO"; return t }, false, true},
		{"the FMC with a vendor the reference leaves open", func(t TcbInfo) TcbInfo { t.Vendor = "ACME"; return t }, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			named, err := Appraise(refs, c.tcb(fmc))
			if named != c.named || (err == nil) != c.pass {
				t.Fatalf("named %v, err %v; want named %v, pass %v", named, err, c.named, c.pass)
			}
		})
	}
}

func TestAppraiseEveryAlgorithmShared(t *testing.T) {
	// A reference with sha-256 and sha-384 accepts evidence in either, and needs both to agree when both are given.
	sha256 := strings.Repeat("cd", 32)
	refs := []RefValue{{Env: DiceEnv{Type: "fw"}, Digests: []FWID{{sha256OID, sha256}, {SHA384OID, fmcDigest}}}}
	for _, c := range []struct {
		fwids []FWID
		pass  bool
	}{
		{[]FWID{{SHA384OID, fmcDigest}}, true},
		{[]FWID{{sha256OID, sha256}}, true},
		{[]FWID{{sha256OID, sha256}, {SHA384OID, fmcDigest}}, true},
		{[]FWID{{sha256OID, sha256}, {SHA384OID, rtDigest}}, false},
	} {
		_, err := Appraise(refs, TcbInfo{Type: "fw", FWIDs: c.fwids})
		if (err == nil) != c.pass {
			t.Fatalf("%v: err %v, want pass %v", c.fwids, err, c.pass)
		}
	}
}
