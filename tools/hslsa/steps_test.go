package hslsa

// The design step names are one list, shared by the spec, hwFlow.step and the
// HBOM schema's design.flow[].step.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Horiodino/hw-slsa/hbom"
)

func TestSchemaUsesDesignStepNames(t *testing.T) {
	var schema Obj
	must(t, json.Unmarshal(hbom.Schema, &schema))
	enum := Strs(schema, "$defs", "flowStep", "properties", "step", "enum")
	if !slices.Equal(enum, DesignStepNames) {
		t.Fatalf("schema flowStep.step enum %v, want %v", enum, DesignStepNames)
	}
}

func TestSpecListsDesignStepNames(t *testing.T) {
	text := string(ok(os.ReadFile(filepath.Join(root, "spec", "hslsa-v0.1.md"))))
	_, table, found := strings.Cut(text, "**Design step names.**")
	if !found {
		t.Fatal("spec has no design step names table")
	}
	table, _, _ = strings.Cut(table, "| `other` |")
	var names []string
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z-]+)` \\|").FindAllStringSubmatch(table, -1) {
		names = append(names, m[1])
	}
	names = append(names, "other")
	if !slices.Equal(names, DesignStepNames) {
		t.Fatalf("spec lists %v, want %v", names, DesignStepNames)
	}
}

func TestOpenLaneStepsMapOntoDesignStepNames(t *testing.T) {
	for _, s := range specSteps {
		if !slices.Contains(DesignStepNames, s.name) {
			t.Errorf("OpenLane mapping names %q, which is not a design step name", s.name)
		}
	}
}

func TestCommittedChipExample(t *testing.T) {
	example := ok(ReadObj(filepath.Join(root, "hbom", "picosoc-sky130.hbom.intoto.json")))
	must(t, ValidateHBOM(example["predicate"]))
	for _, f := range Objs(example, "predicate", "design", "flow") {
		if !slices.Contains(DesignStepNames, S(f, "step")) {
			t.Errorf("example flow step %q is not a design step name", S(f, "step"))
		}
	}
}
