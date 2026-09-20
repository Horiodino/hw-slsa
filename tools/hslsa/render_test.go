package hslsa

// Renderings: the committed examples' CycloneDX and SPDX documents are what
// their HBOMs render to, every HBOM field reaches both formats, both pass
// the official schemas, and a buyer catches a rendering edited after signing.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const renderTime = "2026-10-01T00:00:00Z"

var renderExamples = []string{"picosoc-sky130", "picosoc-devboard"}

func renderExt(format string) string {
	if format == FormatCycloneDX {
		return "cdx"
	}
	return "spdx"
}

func TestCommittedRenderings(t *testing.T) {
	// Each committed example lists both renderings, and each committed rendering is exactly what the HBOM renders to.
	for _, name := range renderExamples {
		stmt := ok(ReadObj(filepath.Join(root, "hbom", name+".hbom.intoto.json")))
		listed := map[string]bool{}
		for _, r := range Objs(stmt, "predicate", "renderings") {
			listed[S(r, "format")] = true
		}
		for _, f := range RenderFormats {
			if !listed[f.Format] {
				t.Errorf("%s does not list a %s rendering", name, f.Format)
			}
			path := filepath.Join(root, "hbom", name+"."+renderExt(f.Format)+".json")
			got, err := CheckRendering(stmt, path, name)
			if err != nil {
				t.Errorf("%s: %v (regenerate with hslsa render --created %s)", name, err, renderTime)
			} else if got != f.Format {
				t.Errorf("%s: %s is %s", name, path, got)
			}
		}
	}
}

// fullHBOM is an HBOM that sets every field the schema has, for coverage.
func fullHBOM() Obj {
	chip := ok(ReadObj(filepath.Join(root, "hbom", "picosoc-sky130.hbom.intoto.json")))
	board := ok(ReadObj(filepath.Join(root, "hbom", "picosoc-devboard.hbom.intoto.json")))
	p := O(chip, "predicate")
	prod := O(p, "product")
	prod["cpe"] = "cpe:2.3:h:example:picosoc-sky130:a0:*:*:*:*:*:*:*"
	O(prod, "manufacturer")["id"] = "lei:5493001KJTIIGC8Y1R12"
	O(prod, "manufacturer")["site"] = "Design center"
	O(prod, "deviceIdentity")["certDigest"] = Obj{"sha384": strings.Repeat("ab", 48)}
	ip := Objs(p, "design", "ipBlocks")[0]
	ip["encrypted"] = true
	O(ip, "supplier")["id"] = "duns:123456789"
	O(p, "design", "pdk")["digest"] = Obj{"gitCommit": "a496cc6dcfea4d9f87c7431adbe08339419a3fbd", "sha512": strings.Repeat("cd", 64)}
	flow := Objs(p, "design", "flow")
	Objs(flow[0], "tools")[0]["digest"] = Obj{"sha3-256": strings.Repeat("ef", 32), "gitCommit": "01afdda1b0e3ca89e503fda08c983a3a66340c5a"}
	fw := Objs(p, "firmware")[1]
	fw["referenceValuesRef"] = Obj{"uri": "https://example.org/fw.corim", "digest": Obj{"sha256": strings.Repeat("12", 32)}, "mediaType": CoRIMMediaType}
	m := O(p, "manufacturing")
	O(m, "fab", "foundry")["id"] = "cage:1ABC2"
	Objs(m, "waferLots")[0]["waferIds"] = []any{"W01", "W02"}
	m["boardAssembly"] = O(board, "predicate", "manufacturing", "boardAssembly")
	p["parts"] = A(board, "predicate", "parts")
	O(Objs(p, "parts")[0], "distributor")["id"] = "uei:ABCDEF123456"
	return chip
}

// leaves lists every string and boolean in v outside renderings[] and the
// statement's _type, which is in-toto's and the same for every HBOM.
func leaves(v any, path string, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			if k == "renderings" || k == "_type" {
				continue
			}
			leaves(c, path+"/"+k, out)
		}
	case []any:
		for _, c := range x {
			leaves(c, path, out)
		}
	case []Obj:
		for _, c := range x {
			leaves(c, path, out)
		}
	case string:
		*out = append(*out, x)
	case bool:
		*out = append(*out, map[bool]string{true: "true", false: "false"}[x])
	}
}

func TestRenderingCarriesEveryField(t *testing.T) {
	stmt := fullHBOM()
	must(t, ValidateHBOM(stmt["predicate"]))
	var values []string
	leaves(normalize(stmt), "", &values)
	for _, f := range RenderFormats {
		data := ok(RenderHBOM(stmt, f.Format, renderTime))
		for _, v := range values {
			quoted := compactJSON(v)
			inner := string(quoted[1 : len(quoted)-1])
			if !strings.Contains(string(data), inner) {
				t.Errorf("%s rendering does not carry %q", f.Format, v)
			}
		}
	}
}

func TestRenderingIsDeterministicAndLeavesOutRenderings(t *testing.T) {
	stmt := ok(ReadObj(filepath.Join(root, "hbom", "picosoc-sky130.hbom.intoto.json")))
	for _, f := range RenderFormats {
		a := ok(RenderHBOM(stmt, f.Format, renderTime))
		other := normalize(stmt).(map[string]any)
		delete(O(other, "predicate"), "renderings")
		if b := ok(RenderHBOM(other, f.Format, renderTime)); string(a) != string(b) {
			t.Errorf("%s rendering depends on renderings[]", f.Format)
		}
		O(other, "predicate", "product")["revision"] = "B0"
		b := ok(RenderHBOM(other, f.Format, renderTime))
		if string(a) == string(b) {
			t.Errorf("%s rendering ignores the product revision", f.Format)
		}
	}
	cdx := ok(decodeJSON(ok(RenderHBOM(stmt, FormatCycloneDX, renderTime))))
	spdx := ok(RenderHBOM(stmt, FormatSPDX, renderTime))
	serial := strings.TrimPrefix(S(cdx, "serialNumber"), "urn:uuid:")
	if !strings.Contains(string(spdx), "urn:uuid:"+serial+"#product") {
		t.Error("the SPDX document and the CycloneDX BOM do not share the HBOM's UUID")
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	stmt := ok(ReadObj(filepath.Join(root, "hbom", "picosoc-sky130.hbom.intoto.json")))
	if _, err := RenderHBOM(stmt, "CycloneDX-1.5", renderTime); err == nil {
		t.Error("rendered an unknown format")
	}
	if _, err := RenderHBOM(stmt, FormatSPDX, "2026-10-01"); err == nil {
		t.Error("accepted a creation time without a time of day")
	}
	bad := normalize(stmt).(map[string]any)
	delete(O(bad, "predicate"), "product")
	if _, err := RenderHBOM(bad, FormatCycloneDX, renderTime); err == nil {
		t.Error("rendered an HBOM that does not match its schema")
	}
}

func TestOfficialSchemasRejectBadRenderings(t *testing.T) {
	stmt := ok(ReadObj(filepath.Join(root, "hbom", "picosoc-sky130.hbom.intoto.json")))
	r := ok(newRenderSource(stmt, renderTime))

	cdx := renderCycloneDX(r)
	must(t, validateRendering(FormatCycloneDX, cdx))
	O(cdx, "metadata", "component")["type"] = "chip"
	if validateRendering(FormatCycloneDX, cdx) == nil {
		t.Error("CycloneDX schema accepted component type chip")
	}

	for name, mutate := range map[string]func(el Obj){
		"unknown property":     func(el Obj) { el["hardware_dieSize"] = "1 mm" },
		"two-letter country":   func(el Obj) { el["country"] = "US" },
		"blank node as spdxId": func(el Obj) { el["spdxId"] = "_:product" },
	} {
		spdx := renderSPDX(r)
		must(t, validateRendering(FormatSPDX, spdx))
		want := "hardware_PhysicalHardware"
		if name == "two-letter country" {
			want = "PhysicalLocation"
		}
		for _, el := range Objs(spdx, "@graph") {
			if S(el, "type") == want {
				mutate(el)
				break
			}
		}
		if validateRendering(FormatSPDX, spdx) == nil {
			t.Errorf("SPDX schema accepted %s", name)
		}
	}
}

func TestLookaheadRegexp(t *testing.T) {
	re := ok(lookaheadRegexp("^(?!_:).+:.+"))
	for s, want := range map[string]bool{"urn:uuid:x#a": true, "_:creationinfo": false, "_x:y": true, "plain": false} {
		if re.MatchString(s) != want {
			t.Errorf("%q: got %v", s, !want)
		}
	}
	if re.String() != "^(?!_:).+:.+" {
		t.Error("pattern not kept")
	}
	if _, err := lookaheadRegexp("^(?=a)b"); err == nil {
		t.Error("compiled a lookahead RE2 does not support")
	}
}

func TestCheckRenderingCatchesEdits(t *testing.T) {
	stmt := ok(ReadObj(filepath.Join(root, "hbom", "picosoc-sky130.hbom.intoto.json")))
	dir := t.TempDir()
	path := filepath.Join(dir, "x.cdx.json")
	must(t, os.WriteFile(path, ok(RenderHBOM(stmt, FormatCycloneDX, renderTime)), 0o644))

	// The same rendering at another time is a valid rendering, but not the one the HBOM lists.
	other := filepath.Join(dir, "later.cdx.json")
	must(t, os.WriteFile(other, ok(RenderHBOM(stmt, FormatCycloneDX, "2026-10-02T00:00:00Z")), 0o644))
	_, err := CheckRendering(stmt, other, "hbom")
	rejects(t, err, "does not have the digest the HBOM lists")

	editJSON(t, path, func(b Obj) {
		O(b, "metadata", "component")["name"] = "another part"
	})
	_, err = CheckRendering(stmt, path, "hbom")
	rejects(t, err, "is not what the signed HBOM renders to")

	must(t, os.WriteFile(path, []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.5"}`), 0o644))
	_, err = CheckRendering(stmt, path, "hbom")
	rejects(t, err, "neither a CycloneDX 1.6 BOM nor an SPDX 3.1-RC1 document")
}

// The buyer's check

func TestRenderingEditedAfterSigning(t *testing.T) {
	bundle := chipBundle(t)
	editJSON(t, filepath.Join(bundle, "att", "hbom.cdx.json"), func(b Obj) {
		O(b, "metadata", "component")["name"] = "another part"
	})
	rejects(t, chipCheck(t, bundle, nil), "hbom: CycloneDX-1.6 rendering hbom.cdx.json is not what the signed HBOM renders to")
}

func TestRenderingMissing(t *testing.T) {
	bundle := chipBundle(t)
	must(t, os.Remove(filepath.Join(bundle, "att", "hbom.spdx.json")))
	rejects(t, chipCheck(t, bundle, nil), "hbom: SPDX-3.1-RC1 rendering file:att/hbom.spdx.json is missing")
}

func TestRenderingOutsideTheBundle(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, "hbom.intoto.json", "product-owner", func(s Obj) {
		Objs(s, "predicate", "renderings")[0]["uri"] = "file:../keys/product-owner.key.pem"
	})
	rejects(t, chipCheck(t, bundle, nil), "hbom: rendering file:../keys/product-owner.key.pem is outside the bundle")
}

func TestRenderingSwappedForAnotherFormat(t *testing.T) {
	bundle := chipBundle(t)
	att := filepath.Join(bundle, "att")
	must(t, copyFile(filepath.Join(att, "hbom.cdx.json"), filepath.Join(att, "hbom.spdx.json")))
	rejects(t, chipCheck(t, bundle, nil), "hbom: file:att/hbom.spdx.json is a CycloneDX-1.6 rendering, the HBOM lists it as SPDX-3.1-RC1")
}

func TestBoardRenderingEditedAfterSigning(t *testing.T) {
	work := boardWork(t)
	editJSON(t, filepath.Join(work, "board", "att", "hbom.spdx.json"), func(d Obj) {
		for _, el := range Objs(d, "@graph") {
			if S(el, "type") == "hardware_PhysicalHardware" && S(el, "name") == flash {
				el["hardware_batchNumber"] = "EXAMPLE-WB-LOT-0666"
			}
		}
	})
	boardRejects(t, work, "board hbom: SPDX-3.1-RC1 rendering hbom.spdx.json is not what the signed HBOM renders to")
}
