package hslsa

// The SPDX 3.1-RC1 rendering, in the JSON-LD serialization. The product is a
// hardware_PhysicalHardware whose category is its HBOM hierarchy level and
// whose batch number is the lot. IP blocks, RTL sources and the PDK are
// software_Package elements, files are software_File elements, and firmware
// images are packages with primary purpose firmware. Each design flow step is
// a build_Build that uses its tools and has its signed record as evidence.
// Each manufacturing step is a SupplyChain action (ManufactureAction,
// AssemblyAction, TestAction) performed by its organization at its site, with
// its signed record as evidence; a board part's distribution record is a
// custody ResponsibilityChangeAction. HBOM fields with no SPDX property travel
// as hbom: entries, in additionalInformation where the class has it and in a
// CdxPropertiesExtension otherwise.

import (
	"fmt"
	"strings"

	"github.com/Horiodino/hw-slsa/hbom/formats"
	"golang.org/x/text/language"
)

var spdxHashAlg = map[string]string{"sha256": "sha256", "sha384": "sha384", "sha512": "sha512", "sha3-256": "sha3_256"}

func spdxHashes(d Obj) []Obj {
	var out []Obj
	for _, alg := range sortedKeys(d) {
		if a, ok := spdxHashAlg[alg]; ok {
			out = append(out, Obj{"type": "Hash", "algorithm": a, "hashValue": S(d, alg)})
		}
	}
	return out
}

func spdxDict(pairs [][2]string) []Obj {
	out := make([]Obj, 0, len(pairs))
	seen := map[string]int{}
	for _, p := range pairs {
		// Dictionary keys are unique; a repeated name gets a counter.
		key := p[0]
		seen[key]++
		if n := seen[key]; n > 1 {
			key = fmt.Sprintf("%s.%d", key, n)
		}
		out = append(out, Obj{"type": "DictionaryEntry", "key": key, "value": p[1]})
	}
	return out
}

func spdxExt(pairs [][2]string) []Obj {
	if len(pairs) == 0 {
		return nil
	}
	var entries []Obj
	for _, p := range pairs {
		entries = append(entries, Obj{"type": "extension_CdxPropertyEntry", "extension_cdxPropName": p[0], "extension_cdxPropValue": p[1]})
	}
	return []Obj{{"type": "extension_CdxPropertiesExtension", "extension_cdxProperty": entries}}
}

// spdxCountry is the ISO 3166-1 alpha-3 code SPDX locations use, from the HBOM's alpha-2 code.
func spdxCountry(alpha2 string) string {
	r, err := language.ParseRegion(alpha2)
	if err != nil {
		return ""
	}
	return r.ISO3()
}

var spdxOrgIDType = map[string]string{"lei": "lei", "duns": "duns", "gln": "gln"}

type spdxBuilder struct {
	ns    string
	graph []Obj
	ids   []string
	n     map[string]int
	dedup map[string]string
}

// nonEmpty lists the ids that are set.
func nonEmpty(ids ...string) []string {
	var out []string
	for _, id := range ids {
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

func (b *spdxBuilder) add(typ, kind string, fields Obj) string {
	b.n[kind]++
	id := fmt.Sprintf("%s%s-%d", b.ns, kind, b.n[kind])
	if kind == "product" {
		id = b.ns + "product"
	}
	el := Obj{"type": typ, "spdxId": id, "creationInfo": "_:creationinfo"}
	for k, v := range fields {
		switch x := v.(type) {
		case string:
			if x == "" {
				continue
			}
		case []Obj:
			if len(x) == 0 {
				continue
			}
		case []string:
			if len(x) == 0 {
				continue
			}
		}
		el[k] = v
	}
	b.graph = append(b.graph, el)
	b.ids = append(b.ids, id)
	return id
}

// once adds an element the first time key is seen and returns its id.
func (b *spdxBuilder) once(key string, build func() string) string {
	if id, ok := b.dedup[key]; ok {
		return id
	}
	id := build()
	b.dedup[key] = id
	return id
}

func (b *spdxBuilder) rel(from, typ string, to ...string) {
	if from == "" || len(to) == 0 {
		return
	}
	b.add("Relationship", "rel", Obj{"from": from, "relationshipType": typ, "to": to})
}

func (b *spdxBuilder) org(org Obj) string {
	if org == nil {
		return ""
	}
	return b.once("org "+string(compactJSON(org)), func() string {
		f := Obj{"name": S(org, "name")}
		var extra [][2]string
		if id := S(org, "id"); id != "" {
			scheme, value, _ := strings.Cut(id, ":")
			ei := Obj{"type": "ExternalIdentifier", "identifier": value}
			if t, ok := spdxOrgIDType[scheme]; ok {
				ei["externalIdentifierType"] = t
			} else {
				ei["externalIdentifierType"] = "other"
				ei["issuingAuthority"] = strings.ToUpper(scheme)
			}
			f["externalIdentifier"] = []Obj{ei}
			extra = append(extra, [2]string{"hbom:id", id})
		}
		for _, k := range []string{"country", "site"} {
			if v := S(org, k); v != "" {
				extra = append(extra, [2]string{"hbom:" + k, v})
			}
		}
		f["extension"] = spdxExt(extra)
		return b.add("Organization", "org", f)
	})
}

// location is where an org did a step: its site and country.
func (b *spdxBuilder) location(org Obj) string {
	if S(org, "site") == "" && S(org, "country") == "" {
		return ""
	}
	return b.once("loc "+S(org, "name")+"|"+S(org, "site")+"|"+S(org, "country"), func() string {
		name := S(org, "name")
		if s := S(org, "site"); s != "" {
			name += ", " + s
		}
		return b.add("PhysicalLocation", "location", Obj{"name": name, "country": spdxCountry(S(org, "country"))})
	})
}

// file is a software_File for an HBOM ref, once per URI and digest.
func (b *spdxBuilder) file(ref Obj, purpose string) string {
	if ref == nil {
		return ""
	}
	return b.once("file "+S(ref, "uri")+string(compactJSON(get(ref, "digest"))), func() string {
		f := Obj{
			"name":                    S(ref, "uri"),
			"software_primaryPurpose": purpose,
			"software_fileKind":       "file",
			"verifiedUsing":           spdxHashes(O(ref, "digest")),
			"contentType":             S(ref, "mediaType"),
		}
		if g := S(ref, "digest", "gitCommit"); g != "" {
			f["extension"] = spdxExt([][2]string{{"hbom:gitCommit", g}})
		}
		return b.add("software_File", "file", f)
	})
}

func (b *spdxBuilder) tool(t Obj) string {
	return b.once("tool "+string(compactJSON(t)), func() string {
		f := Obj{"name": strings.TrimSpace(S(t, "name") + " " + S(t, "version")), "verifiedUsing": spdxHashes(O(t, "digest"))}
		if p := S(t, "purl"); p != "" {
			f["externalIdentifier"] = []Obj{{"type": "ExternalIdentifier", "externalIdentifierType": "packageUrl", "identifier": p}}
		}
		if g := S(t, "digest", "gitCommit"); g != "" {
			f["extension"] = spdxExt([][2]string{{"hbom:gitCommit", g}})
		}
		return b.add("Tool", "tool", f)
	})
}

func (b *spdxBuilder) license(expr string) string {
	return b.once("license "+expr, func() string {
		return b.add("simplelicensing_LicenseExpression", "license", Obj{"simplelicensing_licenseExpression": expr})
	})
}

// ipPurpose is the SPDX primary purpose of an IP block of the given kind.
func ipPurpose(kind string) string {
	if kind == "soft" || kind == "firm" {
		return "source"
	}
	return "library"
}

func renderSPDX(r *renderSource) Obj {
	p := r.pred
	b := &spdxBuilder{ns: "urn:uuid:" + r.uuid + "#", n: map[string]int{}, dedup: map[string]string{}}
	product := O(p, "product")
	design := O(p, "design")

	agent := b.add("SoftwareAgent", "agent", Obj{"name": "hslsa " + RenderToolVersion})
	spec := b.add("Specification", "spec", Obj{
		"name":     "HSLSA HBOM predicate v" + S(p, "hbomVersion"),
		"specType": "spdx:Core/SpecificationType/specification",
		"externalRef": []Obj{{
			"type": "ExternalRef", "externalRefType": "documentation", "locator": []string{S(r.stmt, "predicateType")},
		}},
	})

	partNumber := S(product, "partNumber")
	if partNumber == "" {
		partNumber = S(product, "name")
	}
	lotID := ""
	if lot := lotSubject(r.stmt); lot != nil {
		lotID = strings.TrimPrefix(S(lot, "name"), "urn:hslsa:lot:")
	}
	pf := Obj{
		"name":                           S(product, "name"),
		"hardware_partNumber":            partNumber,
		"hardware_productAgent":          b.org(O(product, "manufacturer")),
		"hardware_hardwareVersion":       S(product, "revision"),
		"hardware_batchNumber":           lotID,
		"hardware_category":              []Obj{{"type": "DefinedType", "definitionSource": spec, "typeFromSource": S(product, "level")}},
		"hardware_additionalInformation": spdxDict(headFields(r)),
	}
	var ext []Obj
	if purl := S(product, "purl"); purl != "" {
		ext = append(ext, Obj{"type": "ExternalIdentifier", "externalIdentifierType": "packageUrl", "identifier": purl})
	}
	if cpe := S(product, "cpe"); cpe != "" {
		t := "cpe22"
		if strings.HasPrefix(cpe, "cpe:2.3:") {
			t = "cpe23"
		}
		ext = append(ext, Obj{"type": "ExternalIdentifier", "externalIdentifierType": t, "identifier": cpe})
	}
	pf["externalIdentifier"] = ext
	prod := b.add("hardware_PhysicalHardware", "product", pf)
	var contains []string

	// Design
	var designInputs []string
	for _, ip := range Objs(design, "ipBlocks") {
		src := O(ip, "source")
		extra := [][2]string{{"hbom:ipKind", S(ip, "kind")}}
		if e, ok := get(ip, "encrypted").(bool); ok {
			extra = append(extra, [2]string{"hbom:encrypted", fmt.Sprint(e)})
		}
		id := b.add("software_Package", "ip", Obj{
			"name":                      S(ip, "name"),
			"software_packageVersion":   S(ip, "version"),
			"suppliedBy":                b.org(O(ip, "supplier")),
			"software_primaryPurpose":   ipPurpose(S(ip, "kind")),
			"software_downloadLocation": vcsLocator(S(src, "uri"), O(src, "digest")),
			"verifiedUsing":             spdxHashes(O(src, "digest")),
			"extension":                 spdxExt(extra),
		})
		if l := S(ip, "license"); l != "" {
			b.rel(id, "hasDeclaredLicense", b.license(l))
		}
		contains = append(contains, id)
		designInputs = append(designInputs, id)
	}
	for _, src := range Objs(design, "rtlSources") {
		name := S(src, "path")
		if name == "" {
			name = S(src, "repo")
		}
		var extra [][2]string
		if l := S(src, "language"); l != "" {
			extra = append(extra, [2]string{"hbom:language", l})
		}
		designInputs = append(designInputs, b.add("software_Package", "rtl", Obj{
			"name":                      name,
			"software_primaryPurpose":   "source",
			"software_downloadLocation": vcsLocator(S(src, "repo"), O(src, "digest")),
			"verifiedUsing":             spdxHashes(O(src, "digest")),
			"extension":                 spdxExt(extra),
		}))
	}
	if pdk := O(design, "pdk"); pdk != nil {
		var extra [][2]string
		if g := S(pdk, "digest", "gitCommit"); g != "" {
			extra = append(extra, [2]string{"hbom:gitCommit", g})
		}
		designInputs = append(designInputs, b.add("software_Package", "pdk", Obj{
			"name":                    S(pdk, "name"),
			"software_packageVersion": S(pdk, "version"),
			"suppliedBy":              b.org(O(pdk, "vendor")),
			"software_primaryPurpose": "library",
			"verifiedUsing":           spdxHashes(O(pdk, "digest")),
			"extension":               spdxExt(append([][2]string{{"hbom:pdk", "true"}}, extra...)),
		}))
	}
	layout := b.file(O(design, "finalLayout"), "data")
	var prevStep string
	for i, step := range Objs(design, "flow") {
		id := b.add("build_Build", "build", Obj{
			"name":            S(step, "step"),
			"build_buildType": DesignFlow,
			"build_buildId":   fmt.Sprintf("%d-%s", i+1, S(step, "step")),
		})
		if i == 0 {
			b.rel(id, "hasInput", designInputs...)
		}
		var tools, outs []string
		for _, t := range Objs(step, "tools") {
			tools = append(tools, b.tool(t))
		}
		for _, o := range Objs(step, "outputs") {
			outs = append(outs, b.file(o, "data"))
		}
		b.rel(id, "usesTool", tools...)
		b.rel(id, "hasOutput", outs...)
		if pr := O(step, "provenanceRef"); pr != nil {
			b.rel(id, "hasEvidence", b.file(pr, "evidence"))
		}
		if prevStep != "" {
			b.rel(prevStep, "follows", id)
		}
		prevStep = id
	}

	// Firmware and parts
	for _, fw := range Objs(p, "firmware") {
		extra := [][2]string{{"hbom:role", S(fw, "role")}}
		if s := S(fw, "storage"); s != "" {
			extra = append(extra, [2]string{"hbom:storage", s})
		}
		id := b.add("software_Package", "firmware", Obj{
			"name":                    S(fw, "name"),
			"software_packageVersion": S(fw, "version"),
			"software_primaryPurpose": "firmware",
			"verifiedUsing":           spdxHashes(O(fw, "digest")),
			"extension":               spdxExt(extra),
		})
		var meta []string
		if s := O(fw, "sbomRef"); s != nil {
			meta = append(meta, b.file(s, "bom"))
		}
		if v := O(fw, "referenceValuesRef"); v != nil {
			meta = append(meta, b.file(v, "evidence"))
		}
		b.rel(id, "hasMetadata", meta...)
		contains = append(contains, id)
	}
	ems := b.org(O(p, "manufacturing", "boardAssembly", "ems"))
	var parts []string
	for _, part := range Objs(p, "parts") {
		var info [][2]string
		for _, rd := range Strs(part, "refDes") {
			info = append(info, [2]string{"hbom:refDes", rd})
		}
		if d := S(part, "dateCode"); d != "" {
			info = append(info, [2]string{"hbom:dateCode", d})
		}
		if a, ok := get(part, "authorized").(bool); ok {
			info = append(info, [2]string{"hbom:authorized", fmt.Sprint(a)})
		}
		id := b.add("hardware_PhysicalHardware", "part", Obj{
			"name":                           S(part, "mpn"),
			"hardware_partNumber":            S(part, "mpn"),
			"hardware_productAgent":          b.org(O(part, "manufacturer")),
			"hardware_batchNumber":           S(part, "lot"),
			"suppliedBy":                     b.org(O(part, "distributor")),
			"hardware_additionalInformation": spdxDict(info),
		})
		if h := O(part, "hbomRef"); h != nil {
			b.rel(id, "hasMetadata", b.file(h, "bom"))
		}
		if d := O(part, "distributionRef"); d != nil {
			rec := b.file(d, "evidence")
			if ems != "" {
				f := Obj{
					"name":                                "distribution of " + S(part, "mpn"),
					"supplychain_current":                 ems,
					"supplychain_previous":                b.org(O(part, "distributor")),
					"supplychain_responsibilityCategory":  "custody",
					"supplychain_responsibilityChangedOn": []string{id},
				}
				b.rel(b.add("supplychain_ResponsibilityChangeAction", "transfer", f), "hasEvidence", rec)
			} else {
				b.rel(id, "hasEvidence", rec)
			}
		}
		parts = append(parts, id)
		contains = append(contains, id)
	}

	// Manufacturing
	var prevAct string
	for _, a := range mfgActions(p) {
		typ := map[string]string{
			"fab": "supplychain_ManufactureAction", "assembly": "supplychain_AssemblyAction",
			"test": "supplychain_TestAction", "boardAssembly": "supplychain_AssemblyAction",
		}[a.kind]
		fields := mfgFields(a)
		if a.kind == "fab" {
			fields = append(fields, waferLotFields(p)...)
		}
		org := mfgOrg(a)
		id := b.add(typ, "action", Obj{
			"name":                  mfgName(a),
			"actionLocation":        nonEmpty(b.location(org)),
			"additionalInformation": spdxDict(fields),
		})
		b.rel(id, "performedBy", b.org(org))
		switch a.kind {
		case "fab":
			if layout != "" {
				b.rel(id, "hasInput", layout)
			}
		case "assembly":
			b.rel(id, "hasOutput", prod)
		case "test":
			b.rel(id, "hasInput", prod)
			if prog := O(a.block, "program"); prog != nil {
				b.rel(id, "usesTool", b.tool(prog))
			}
		case "boardAssembly":
			b.rel(id, "hasInput", parts...)
			if layout != "" {
				b.rel(id, "hasInput", layout)
			}
			b.rel(id, "hasOutput", prod)
		}
		if rec := mfgActionRecord(a); rec != nil {
			b.rel(id, "hasEvidence", b.file(rec, "evidence"))
		}
		if prevAct != "" {
			b.rel(prevAct, "follows", id)
		}
		prevAct = id
	}
	b.rel(prod, "contains", contains...)

	elements := append([]string{}, b.ids...)
	bom := b.ns + "bom"
	docID := b.ns + "document"
	profiles := []string{"core", "hardware", "supplyChain", "software", "build", "simpleLicensing", "extension"}
	graph := []Obj{
		{"type": "CreationInfo", "@id": "_:creationinfo", "created": r.created, "createdBy": []string{agent}, "specVersion": SPDXSpecVersion},
		{
			"type": "SpdxDocument", "spdxId": docID, "creationInfo": "_:creationinfo",
			"name":               "HBOM of " + S(product, "name") + " (HSLSA)",
			"profileConformance": profiles,
			"rootElement":        []string{bom},
			"element":            append([]string{bom}, elements...),
		},
		{
			"type": "Bom", "spdxId": bom, "creationInfo": "_:creationinfo",
			"name":               "HBOM of " + S(product, "name"),
			"profileConformance": profiles,
			"rootElement":        []string{prod},
			"element":            elements,
		},
	}
	return Obj{"@context": formats.SPDXContext, "@graph": append(graph, b.graph...)}
}
