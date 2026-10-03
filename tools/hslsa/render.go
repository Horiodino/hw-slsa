package hslsa

// Render: the HBOM as a CycloneDX 1.6 BOM and as an SPDX 3.1 (release
// candidate 1) document, so standard SBOM tooling can read it.
//
// A rendering is derived from the HBOM statement and carries no signature of
// its own. It is deterministic: the same statement and creation time give the
// same bytes. The product owner renders before signing and lists each
// rendering by digest in the HBOM's renderings[]; a reader re-renders the
// signed HBOM and compares bytes, so a rendering that says something the
// signed HBOM does not is caught. A rendering leaves out renderings[] itself,
// so the HBOM can name its renderings without a cycle.

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/Horiodino/hw-slsa/hbom/formats"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

const (
	FormatCycloneDX = "CycloneDX-1.6"
	FormatSPDX      = "SPDX-3.1-RC1"
	// SPDXSpecVersion is the creationInfo.specVersion of the SPDX rendering.
	SPDXSpecVersion = "3.1.0-rc1"
	// RenderToolVersion names this renderer in both documents.
	RenderToolVersion = "0.1"
)

// RenderFormats lists each format with the file name a bundle keeps it under, next to att/hbom.intoto.json.
var RenderFormats = []struct{ Format, File string }{
	{FormatCycloneDX, "hbom.cdx.json"},
	{FormatSPDX, "hbom.spdx.json"},
}

// renderSource is the statement a rendering is made from, without renderings[].
type renderSource struct {
	stmt, pred Obj
	digest     string // sha256 of the canonical statement
	uuid       string // UUIDv5 of the digest, shared by both renderings
	created    string
}

func newRenderSource(stmt Obj, created string) (*renderSource, error) {
	if S(stmt, "predicateType") != HBOMType {
		return nil, fmt.Errorf("not an HBOM statement: predicate type %q", S(stmt, "predicateType"))
	}
	if err := ValidateHBOM(get(stmt, "predicate")); err != nil {
		return nil, err
	}
	if !timestampRE.MatchString(created) {
		return nil, fmt.Errorf("creation time %q is not YYYY-MM-DDTHH:MM:SSZ", created)
	}
	src, _ := normalize(stmt).(map[string]any)
	pred := O(src, "predicate")
	delete(pred, "renderings")
	digest := sha256Bytes(compactJSON(src))
	return &renderSource{stmt: src, pred: pred, digest: digest, uuid: uuidV5(urlNamespace, "urn:hslsa:hbom:sha256:"+digest), created: created}, nil
}

var timestampRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// urlNamespace is the RFC 9562 namespace ID for URLs.
var urlNamespace = [16]byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}

// uuidV5 is the name-based UUID of RFC 9562 section 5.5.
func uuidV5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	b := h.Sum(nil)[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// RenderHBOM renders an HBOM statement in format, created at created
// (YYYY-MM-DDTHH:MM:SSZ), and checks the result against the format's official
// JSON Schema.
func RenderHBOM(stmt Obj, format, created string) ([]byte, error) {
	r, err := newRenderSource(stmt, created)
	if err != nil {
		return nil, err
	}
	var doc Obj
	switch format {
	case FormatCycloneDX:
		doc = renderCycloneDX(r)
	case FormatSPDX:
		doc = renderSPDX(r)
	default:
		return nil, fmt.Errorf("unknown format %q (choose from %s, %s)", format, FormatCycloneDX, FormatSPDX)
	}
	if err := validateRendering(format, doc); err != nil {
		return nil, err
	}
	return encode(doc, true)
}

// renderingInfo reads which format a rendering is in and when it was created.
func renderingInfo(data []byte) (format, created string, err error) {
	v, err := decodeJSON(data)
	if err != nil {
		return "", "", err
	}
	switch {
	case S(v, "bomFormat") == "CycloneDX" && S(v, "specVersion") == "1.6":
		return FormatCycloneDX, S(v, "metadata", "timestamp"), nil
	case S(v, "@context") == formats.SPDXContext:
		for _, el := range Objs(v, "@graph") {
			if S(el, "type") == "CreationInfo" {
				return FormatSPDX, S(el, "created"), nil
			}
		}
		return "", "", fmt.Errorf("SPDX document has no CreationInfo")
	}
	return "", "", fmt.Errorf("neither a CycloneDX 1.6 BOM nor an SPDX 3.1-RC1 document")
}

// CheckRendering checks that the rendering at path is exactly what the HBOM
// statement renders to, and, when the HBOM lists a rendering in that format,
// that the file has the digest it lists. It returns the format.
func CheckRendering(stmt Obj, path, label string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	format, created, err := renderingInfo(data)
	if err != nil {
		return "", failf("%s: %s: %v", label, filepath.Base(path), err)
	}
	want, err := RenderHBOM(stmt, format, created)
	if err != nil {
		return "", failf("%s: cannot re-render %s: %v", label, filepath.Base(path), err)
	}
	if !bytes.Equal(data, want) {
		return "", failf("%s: %s rendering %s is not what the signed HBOM renders to", label, format, filepath.Base(path))
	}
	for _, r := range Objs(stmt, "predicate", "renderings") {
		if S(r, "format") == format && S(r, "digest", "sha256") != sha256Bytes(data) {
			return "", failf("%s: %s rendering %s does not have the digest the HBOM lists", label, format, filepath.Base(path))
		}
	}
	return format, nil
}

// addRenderings renders the statement in every format into dir and lists
// each in the predicate's renderings[], with uriPrefix before the file name.
func addRenderings(stmt Obj, dir, uriPrefix string) error {
	var list []Obj
	created := Now()
	for _, f := range RenderFormats {
		data, err := RenderHBOM(stmt, f.Format, created)
		if err != nil {
			return fmt.Errorf("render %s: %w", f.Format, err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, f.File), data, 0o644); err != nil {
			return err
		}
		list = append(list, Obj{"format": f.Format, "uri": uriPrefix + f.File, "digest": Obj{"sha256": sha256Bytes(data)}})
	}
	O(stmt, "predicate")["renderings"] = list
	return nil
}

// checkRenderings is the buyer's check of the renderings a signed HBOM lists
// as files in the bundle: each must have its listed digest and be exactly what
// the HBOM renders to as signed, before any withheld field is revealed.
// Renderings elsewhere are left to the reader. Call it only on an envelope
// whose signature has been checked.
func checkRenderings(bundle, envelope, label string) ([]string, error) {
	hb, err := DecodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	var checked []string
	for _, r := range Objs(hb, "predicate", "renderings") {
		uri := S(r, "uri")
		if !strings.HasPrefix(uri, "file:") {
			continue
		}
		rel := filepath.FromSlash(strings.TrimPrefix(uri, "file:"))
		if !filepath.IsLocal(rel) {
			return nil, failf("%s: rendering %s is outside the bundle", label, uri)
		}
		path := filepath.Join(bundle, rel)
		if _, err := os.Stat(path); err != nil {
			return nil, failf("%s: %s rendering %s is missing", label, S(r, "format"), uri)
		}
		format, err := CheckRendering(hb, path, label)
		if err != nil {
			return nil, err
		}
		if format != S(r, "format") {
			return nil, failf("%s: %s is a %s rendering, the HBOM lists it as %s", label, uri, format, S(r, "format"))
		}
		checked = append(checked, format)
	}
	return checked, nil
}

// renderingsCheck is the last step of a buyer's check, after the whole
// chain: the renderings are derived from the HBOM, so a failure elsewhere is
// reported first.
func renderingsCheck(bundle, envelope, label string) error {
	checked, err := checkRenderings(bundle, envelope, label)
	if err != nil {
		return err
	}
	if len(checked) > 0 {
		fmt.Printf("%s renderings check: PASSED, %s match the signed HBOM\n", label, strings.Join(checked, " and "))
	}
	return nil
}

// Validation against the official schemas

var (
	renderSchemasOnce sync.Once
	renderSchemas     map[string]*jsonschema.Schema
	renderSchemasErr  error
)

func compileRenderSchemas() (map[string]*jsonschema.Schema, error) {
	renderSchemasOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.UseRegexpEngine(lookaheadRegexp)
		for id, data := range map[string][]byte{
			formats.CycloneDXSchemaID:          formats.CycloneDXSchema,
			formats.CycloneDXLicenseSchemaID:   formats.CycloneDXLicenseSchema,
			formats.CycloneDXSignatureSchemaID: formats.CycloneDXSignatureSchema,
			formats.SPDXSchemaID:               formats.SPDXSchema,
		} {
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
			if err != nil {
				renderSchemasErr = fmt.Errorf("%s: %w", id, err)
				return
			}
			if err := c.AddResource(id, doc); err != nil {
				renderSchemasErr = err
				return
			}
		}
		out := map[string]*jsonschema.Schema{}
		for format, id := range map[string]string{FormatCycloneDX: formats.CycloneDXSchemaID, FormatSPDX: formats.SPDXSchemaID} {
			s, err := c.Compile(id)
			if err != nil {
				renderSchemasErr = fmt.Errorf("%s schema: %w", format, err)
				return
			}
			out[format] = s
		}
		renderSchemas = out
	})
	return renderSchemas, renderSchemasErr
}

// validateRendering checks a rendering against its format's official JSON Schema.
func validateRendering(format string, doc Obj) error {
	schemas, err := compileRenderSchemas()
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(compactJSON(doc)))
	if err != nil {
		return err
	}
	err = schemas[format].Validate(inst)
	if err == nil {
		return nil
	}
	ve, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return fmt.Errorf("%s rendering does not match its schema: %v", format, err)
	}
	// The SPDX schema checks each graph node against every class, so the
	// deepest cause is the most useful one to show.
	deepest := ve
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.InstanceLocation) > len(deepest.InstanceLocation) {
			deepest = e
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	msg := deepest.ErrorKind.LocalizedString(message.NewPrinter(language.English))
	return fmt.Errorf("%s rendering does not match its schema at /%s: %s", format, strings.Join(deepest.InstanceLocation, "/"), msg)
}

// lookaheadRegexp compiles schema patterns with Go's regexp, except a leading
// negative lookahead on a literal, ^(?!lit)rest, which RE2 lacks: that is
// checked as "does not start with lit" and ^rest. The SPDX 3.1-RC1 schema's
// IRI pattern ^(?!_:).+:.+ is the one such pattern.
func lookaheadRegexp(pattern string) (jsonschema.Regexp, error) {
	if strings.HasPrefix(pattern, "^(?!") {
		if end := strings.Index(pattern, ")"); end > 0 {
			lit := pattern[len("^(?!"):end]
			if regexp.QuoteMeta(lit) == lit {
				rest, err := regexp.Compile("^" + pattern[end+1:])
				if err != nil {
					return nil, err
				}
				return notPrefixRegexp{pattern, lit, rest}, nil
			}
		}
	}
	return regexp.Compile(pattern)
}

type notPrefixRegexp struct {
	pattern, lit string
	rest         *regexp.Regexp
}

func (r notPrefixRegexp) MatchString(s string) bool {
	return !strings.HasPrefix(s, r.lit) && r.rest.MatchString(s)
}

func (r notPrefixRegexp) String() string { return r.pattern }

// Shared mapping helpers

// subjectValue is how both renderings write an in-toto subject: name and digests.
func subjectValue(s Obj) string {
	parts := []string{S(s, "name")}
	for _, alg := range sortedKeys(O(s, "digest")) {
		parts = append(parts, alg+":"+S(s, "digest", alg))
	}
	return strings.Join(parts, " ")
}

// lotSubject is the HBOM's urn:hslsa:lot: subject, or nil.
func lotSubject(stmt Obj) Obj {
	for _, s := range Objs(stmt, "subject") {
		if strings.HasPrefix(S(s, "name"), "urn:hslsa:lot:") {
			return s
		}
	}
	return nil
}

// refName is a short name for the file a ref points at: the last path segment of its URI.
func refName(ref Obj) string {
	uri := S(ref, "uri")
	if i := strings.LastIndexAny(uri, "/:"); i >= 0 && i < len(uri)-1 {
		return uri[i+1:]
	}
	return uri
}

// vcsLocator is the SPDX VCS locator for a source: git+<uri>@<commit> when the digest is a git commit.
func vcsLocator(uri string, digest Obj) string {
	if c := S(digest, "gitCommit"); c != "" && uri != "" {
		if strings.HasPrefix(uri, "git+") {
			return uri + "@" + c
		}
		return "git+" + uri + "@" + c
	}
	return uri
}

// orgFields lists an org's fields as name/value pairs under prefix, in a fixed order.
func orgFields(prefix string, org Obj) [][2]string {
	var out [][2]string
	for _, k := range []string{"name", "id", "country", "site"} {
		if v := S(org, k); v != "" {
			out = append(out, [2]string{prefix + "." + k, v})
		}
	}
	return out
}

// orgExtra is orgFields without the name, for an org whose name the format holds natively.
func orgExtra(prefix string, org Obj) [][2]string {
	var out [][2]string
	for _, f := range orgFields(prefix, org) {
		if f[0] != prefix+".name" {
			out = append(out, f)
		}
	}
	return out
}

// mfgActions lists the manufacturing blocks in the order the parts move
// through them: fab, wafer sort, packaging, other tests, board assembly.
type mfgAction struct {
	kind  string // fab, test, assembly, boardAssembly
	block Obj
	index int // test[] index
}

func mfgActions(pred Obj) []mfgAction {
	m := O(pred, "manufacturing")
	var out []mfgAction
	if fab := O(m, "fab"); fab != nil {
		out = append(out, mfgAction{"fab", fab, 0})
	}
	tests := Objs(m, "test")
	for i, t := range tests {
		if S(t, "stage") == "wafer-sort" {
			out = append(out, mfgAction{"test", t, i})
		}
	}
	if asm := O(m, "assembly"); asm != nil {
		out = append(out, mfgAction{"assembly", asm, 0})
	}
	for i, t := range tests {
		if S(t, "stage") != "wafer-sort" {
			out = append(out, mfgAction{"test", t, i})
		}
	}
	if ba := O(m, "boardAssembly"); ba != nil {
		out = append(out, mfgAction{"boardAssembly", ba, 0})
	}
	return out
}

// waferLotFields are the wafer lots as name/value pairs, attached to the fab step.
func waferLotFields(pred Obj) [][2]string {
	var out [][2]string
	for i, l := range Objs(pred, "manufacturing", "waferLots") {
		p := fmt.Sprintf("hbom:waferLots.%d.", i)
		out = append(out, [2]string{p + "lotId", S(l, "lotId")})
		if d := S(l, "startDate"); d != "" {
			out = append(out, [2]string{p + "startDate", d})
		}
		for _, w := range Strs(l, "waferIds") {
			out = append(out, [2]string{p + "waferId", w})
		}
	}
	return out
}

// mfgFields are a manufacturing block's own fields (not its org or record) as name/value pairs.
func mfgFields(a mfgAction) [][2]string {
	var out [][2]string
	add := func(k string) {
		if v := S(a.block, k); v != "" {
			out = append(out, [2]string{"hbom:" + k, v})
		}
	}
	switch a.kind {
	case "fab":
		out = append(out, orgFields("hbom:foundry", O(a.block, "foundry"))...)
		add("processNode")
		add("maskSetId")
		add("shuttle")
	case "assembly":
		out = append(out, orgFields("hbom:osat", O(a.block, "osat"))...)
		add("packageType")
		add("assemblyLot")
		add("dateCode")
	case "test":
		out = append(out, orgFields("hbom:site", O(a.block, "site"))...)
		add("stage")
	case "boardAssembly":
		out = append(out, orgFields("hbom:ems", O(a.block, "ems"))...)
		add("boardLot")
	}
	return out
}

// mfgName names a manufacturing step as the spec does.
func mfgName(a mfgAction) string {
	switch a.kind {
	case "fab":
		return "wafer fabrication"
	case "assembly":
		return "packaging"
	case "boardAssembly":
		return "board assembly"
	}
	return S(a.block, "stage")
}

// mfgOrg is the organization that performed a manufacturing step.
func mfgOrg(a mfgAction) Obj {
	switch a.kind {
	case "fab":
		return O(a.block, "foundry")
	case "assembly":
		return O(a.block, "osat")
	case "boardAssembly":
		return O(a.block, "ems")
	}
	return O(a.block, "site")
}

// mfgActionRecord is the signed record a manufacturing step points at.
func mfgActionRecord(a mfgAction) Obj {
	if a.kind == "test" {
		return O(a.block, "resultsRef")
	}
	return O(a.block, "attestationRef")
}

// headFields are the statement-level facts both renderings carry as hbom: properties.
func headFields(r *renderSource) [][2]string {
	out := [][2]string{{"hbom:predicateType", S(r.stmt, "predicateType")}, {"hbom:hbomVersion", S(r.pred, "hbomVersion")}}
	for _, s := range Objs(r.stmt, "subject") {
		out = append(out, [2]string{"hbom:subject", subjectValue(s)})
	}
	p := O(r.pred, "product")
	out = append(out, [2]string{"hbom:level", S(p, "level")})
	if v := S(p, "partNumber"); v != "" {
		out = append(out, [2]string{"hbom:partNumber", v})
	}
	out = append(out, orgFields("hbom:manufacturer", O(p, "manufacturer"))...)
	id := O(p, "deviceIdentity")
	for _, k := range []string{"scheme", "serial"} {
		if v := S(id, k); v != "" {
			out = append(out, [2]string{"hbom:deviceIdentity." + k, v})
		}
	}
	for _, alg := range sortedKeys(O(id, "certDigest")) {
		out = append(out, [2]string{"hbom:deviceIdentity.certDigest", alg + ":" + S(id, "certDigest", alg)})
	}
	for _, c := range Strs(r.pred, "claimedLevels") {
		out = append(out, [2]string{"hbom:claimedLevel", c})
	}
	for _, red := range Objs(r.pred, "redactions") {
		for _, alg := range sortedKeys(O(red, "saltedDigest")) {
			out = append(out, [2]string{"hbom:redaction", S(red, "path") + " " + alg + ":" + S(red, "saltedDigest", alg)})
		}
	}
	return out
}
