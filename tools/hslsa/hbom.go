package hslsa

// HBOM: build the product owner's bill of materials for the test part, validate it, sign it.

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Horiodino/hw-slsa/hbom"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

func hbomSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(hbom.Schema))
		if err != nil {
			schemaErr = err
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(hbom.SchemaID, doc); err != nil {
			schemaErr = err
			return
		}
		schema, schemaErr = c.Compile(hbom.SchemaID)
	})
	return schema, schemaErr
}

// ValidateHBOM checks an HBOM predicate against the committed JSON Schema (draft 2020-12).
func ValidateHBOM(predicate any) error {
	sch, err := hbomSchema()
	if err != nil {
		return fmt.Errorf("HBOM schema: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(compactJSON(predicate)))
	if err != nil {
		return err
	}
	err = sch.Validate(inst)
	if err == nil {
		return nil
	}
	ve, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return failf("HBOM does not match its schema: %v", err)
	}
	for len(ve.Causes) > 0 {
		ve = ve.Causes[0]
	}
	msg := ve.ErrorKind.LocalizedString(message.NewPrinter(language.English))
	return failf("HBOM does not match its schema at /%s: %s", strings.Join(ve.InstanceLocation, "/"), msg)
}

func attRef(bundle, name string) Obj {
	return Obj{"uri": "file:att/" + name, "digest": fileDigest(filepath.Join(bundle, "att", name))}
}

// fileRef points at a file in the bundle by relative path and digest.
func fileRef(bundle, rel string) Obj {
	return Obj{"uri": "file:" + rel, "digest": fileDigest(filepath.Join(bundle, rel))}
}

// flowEntries lists each design step for the HBOM's design.flow, named by
// the hwFlow.step of its record.
func flowEntries(bundle string, steps []string) ([]Obj, error) {
	var flow []Obj
	for _, step := range steps {
		stmt, err := DecodeEnvelope(filepath.Join(bundle, "att", AttName(step)))
		if err != nil {
			return nil, err
		}
		tools := []Obj{}
		for _, t := range Objs(stmt, "predicate", "hwFlow", "tools") {
			tools = append(tools, Obj{"name": t["name"], "version": t["version"], "digest": t["digest"]})
		}
		if len(tools) == 0 {
			tools = []Obj{{"name": "hslsa", "version": "0.1"}}
		}
		name := S(stmt, "predicate", "hwFlow", "step")
		if !contains(DesignStepNames, name) {
			return nil, fmt.Errorf("%s: hwFlow.step %q is not a design step name", AttName(step), name)
		}
		flow = append(flow, Obj{"step": name, "tools": tools, "provenanceRef": attRef(bundle, AttName(step))})
	}
	return flow, nil
}

// releasedSubject is the first subject of the design release record.
func releasedSubject(bundle string) (Obj, error) {
	rel, err := DecodeEnvelope(filepath.Join(bundle, "att", AttName("release")))
	if err != nil {
		return nil, err
	}
	subjects := Objs(rel, "subject")
	if len(subjects) == 0 {
		return nil, fmt.Errorf("design release has no subject")
	}
	return subjects[0], nil
}

// manufacturingBlock is the HBOM's manufacturing section for the chip examples.
func manufacturingBlock(bundle string, sc Obj) Obj {
	fab, pkg, ft, sort := O(sc, "fab"), O(sc, "packaging"), O(sc, "finalTest"), O(sc, "sort")
	return Obj{
		"fab": Obj{
			"foundry":        get(fab, "site"),
			"processNode":    get(fab, "processNode"),
			"maskSetId":      get(fab, "maskSetId"),
			"attestationRef": attRef(bundle, MfgAtt["wafer-fab"]),
		},
		"waferLots": []Obj{{"lotId": get(sc, "waferLot", "lotId"), "waferIds": get(sc, "waferLot", "wafers")}},
		"assembly": Obj{
			"osat":           get(pkg, "site"),
			"packageType":    get(pkg, "packageType"),
			"assemblyLot":    get(pkg, "assemblyLot"),
			"attestationRef": attRef(bundle, MfgAtt["packaging"]),
		},
		"test": []Obj{
			{"stage": "wafer-sort", "site": get(sort, "site"), "program": get(sort, "program"), "resultsRef": attRef(bundle, MfgAtt["wafer-sort"])},
			{"stage": "final-test", "site": get(ft, "site"), "program": get(ft, "program"), "resultsRef": attRef(bundle, MfgAtt["final-test"])},
		},
	}
}

// signHBOM validates the predicate and signs it over the released design and the shipped lot.
func signHBOM(bundle string, final Obj, lotID string, shipped []string, predicate Obj, key string) error {
	if err := ValidateHBOM(predicate); err != nil {
		return err
	}
	lot, err := LotDigest(shipped)
	if err != nil {
		return err
	}
	subjects := []Obj{rd(S(final, "name"), S(final, "digest", "sha256")), rd("urn:hslsa:lot:"+lotID, lot)}
	stmt, err := statement(subjects, HBOMType, predicate)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	_, err = Sign(stmt, signer, filepath.Join(bundle, "att", "hbom.intoto.json"))
	return err
}

// BuildHBOM builds, validates and signs the PicoRV32 example's HBOM.
func BuildHBOM(bundle, lockPath, scenarioPath, key string) error {
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	src := O(lock, "source")
	flow, err := flowEntries(bundle, append(append([]string{}, DesignSteps...), "release"))
	if err != nil {
		return err
	}
	final, err := releasedSubject(bundle)
	if err != nil {
		return err
	}
	shipped, err := ReadUnits(filepath.Join(bundle, "artifacts", "shipped-lot.txt"))
	if err != nil {
		return err
	}
	var rtl []Obj
	files := O(src, "files")
	for _, name := range sortedKeys(files) {
		rtl = append(rtl, Obj{"repo": get(src, "repo"), "path": name, "digest": Obj{"sha256": files[name]}, "language": "Verilog"})
	}
	predicate := Obj{
		"hbomVersion": "0.1",
		"product":     get(sc, "product"),
		"design": Obj{
			"ipBlocks": []Obj{{
				"name":     get(lock, "design"),
				"kind":     "soft",
				"supplier": Obj{"name": "YosysHQ"},
				"license":  "ISC",
				"source":   Obj{"uri": get(src, "repo"), "digest": Obj{"gitCommit": get(src, "commit")}},
			}},
			"rtlSources":  nonNil(rtl),
			"flow":        flow,
			"finalLayout": Obj{"uri": "file:artifacts/" + S(final, "name"), "digest": get(final, "digest")},
		},
		"manufacturing": manufacturingBlock(bundle, sc),
	}
	if err := signHBOM(bundle, final, S(sc, "finalTest", "lotId"), shipped, predicate, key); err != nil {
		return err
	}
	fmt.Printf("hbom: signed, %d flow steps, lot of %d units\n", len(flow), len(shipped))
	return nil
}
