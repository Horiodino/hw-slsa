package hslsa

// The NIST IR 8536 profile maps every step and record type the spec defines,
// so a step or predicate added to the spec without a mapping fails here.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// firstColumn returns the first cell of each row of the table that follows
// heading in text, skipping the header and separator rows.
func firstColumn(t *testing.T, text, heading string) []string {
	t.Helper()
	_, rest, found := strings.Cut(text, heading)
	if !found {
		t.Fatalf("no %q in the spec", heading)
	}
	var cells []string
	inTable := false
	for _, line := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(line, "|") {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		cells = append(cells, strings.TrimSpace(strings.Split(line, "|")[1]))
	}
	if len(cells) < 3 {
		t.Fatalf("table after %q has no rows", heading)
	}
	return cells[2:]
}

func TestProfileMapsEveryStepAndRecord(t *testing.T) {
	spec := string(ok(os.ReadFile(filepath.Join(root, "spec", "hslsa-v0.1.md"))))
	profile := string(ok(os.ReadFile(filepath.Join(root, "spec", "nist-ir-8536-profile.md"))))
	_, events, _ := strings.Cut(profile, "## Events")
	events, _, _ = strings.Cut(events, "\n## ")
	_, types, _ := strings.Cut(profile, "### Data types")
	types, _, _ = strings.Cut(types, "\n## ")
	for _, step := range firstColumn(t, spec, "### Steps") {
		if !strings.Contains(events, "| "+step+" |") {
			t.Errorf("profile's Events table does not map step %q", step)
		}
	}
	for _, record := range firstColumn(t, spec, "### Predicate types") {
		if !strings.Contains(types, "| "+record+" |") {
			t.Errorf("profile's Data types table does not map record %q", record)
		}
	}
	for _, link := range regexp.MustCompile(`\]\(hslsa-v0\.1\.md#([a-z0-9-]+)\)`).FindAllStringSubmatch(profile, -1) {
		if !regexp.MustCompile(`(?mi)^#+ ` + strings.ReplaceAll(link[1], "-", "[ -]") + `$`).MatchString(spec) {
			t.Errorf("profile links to spec anchor #%s, which has no heading", link[1])
		}
	}
}

func TestSchemaOrgIdentifiers(t *testing.T) {
	example := ok(ReadObj(filepath.Join(root, "hbom", "picosoc-sky130.hbom.intoto.json")))
	pred := O(example, "predicate")
	fab := O(pred, "manufacturing", "fab", "foundry")
	for _, id := range []string{"lei:5493001KJTIIGC8Y1R12", "duns:123456789", "cage:1ABC2", "uei:ABCDEFGH1234", "gln:0614141000005"} {
		fab["id"] = id
		if err := ValidateHBOM(pred); err != nil {
			t.Errorf("org id %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"123456789", "vat:DE123", "duns:"} {
		fab["id"] = id
		if ValidateHBOM(pred) == nil {
			t.Errorf("org id %q accepted", id)
		}
	}
}
