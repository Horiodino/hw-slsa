package hslsa

// The CycloneDX 1.6 rendering. The product is metadata.component, a device.
// IP blocks, RTL sources, the PDK, the final layout, firmware images and board
// parts are components the product depends on. The design flow and the
// manufacturing steps are formulation workflows whose tasks name their tools
// and point at their signed records as attestation outputs. HBOM fields with
// no CycloneDX equivalent travel as properties prefixed hbom:, as the spec says.

import (
	"fmt"
	"strings"
)

var cdxHashAlg = map[string]string{"sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "sha3-256": "SHA3-256"}

// cdxHashes maps a digest set to CycloneDX hashes; gitCommit has no CycloneDX algorithm.
func cdxHashes(d Obj) []Obj {
	var out []Obj
	for _, alg := range sortedKeys(d) {
		if a, ok := cdxHashAlg[alg]; ok {
			out = append(out, Obj{"alg": a, "content": S(d, alg)})
		}
	}
	return out
}

func cdxProps(pairs [][2]string) []Obj {
	out := make([]Obj, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, Obj{"name": p[0], "value": p[1]})
	}
	return out
}

// cdxOrg is an organizational entity: name, and country and site as its address.
func cdxOrg(org Obj) Obj {
	out := Obj{"name": S(org, "name")}
	addr := Obj{}
	if c := S(org, "country"); c != "" {
		addr["country"] = c
	}
	if s := S(org, "site"); s != "" {
		addr["locality"] = s
	}
	if len(addr) > 0 {
		out["address"] = addr
	}
	return out
}

// cdxRef is an external reference for an HBOM ref (uri and digest).
func cdxRef(typ string, ref Obj, comment string) Obj {
	out := Obj{"type": typ, "url": S(ref, "uri")}
	if h := cdxHashes(O(ref, "digest")); len(h) > 0 {
		out["hashes"] = h
	}
	var notes []string
	if comment != "" {
		notes = append(notes, comment)
	}
	if c := S(ref, "digest", "gitCommit"); c != "" {
		notes = append(notes, "git commit "+c)
	}
	if m := S(ref, "mediaType"); m != "" {
		notes = append(notes, "media type "+m)
	}
	if len(notes) > 0 {
		out["comment"] = strings.Join(notes, "; ")
	}
	return out
}

func setStr(o Obj, key, value string) {
	if value != "" {
		o[key] = value
	}
}

func setList(o Obj, key string, list []Obj) {
	if len(list) > 0 {
		o[key] = list
	}
}

type cdxBuilder struct {
	components []Obj
	tools      []Obj
	toolRefs   map[string]string
}

// tool adds a tool to the formulation once and returns its bom-ref.
func (b *cdxBuilder) tool(t Obj) string {
	key := string(compactJSON(t))
	if ref, ok := b.toolRefs[key]; ok {
		return ref
	}
	ref := fmt.Sprintf("tool-%d", len(b.tools)+1)
	c := Obj{"type": "application", "bom-ref": ref, "name": S(t, "name"), "version": S(t, "version")}
	setStr(c, "purl", S(t, "purl"))
	setList(c, "hashes", cdxHashes(O(t, "digest")))
	if g := S(t, "digest", "gitCommit"); g != "" {
		c["properties"] = cdxProps([][2]string{{"hbom:gitCommit", g}})
	}
	b.tools = append(b.tools, c)
	b.toolRefs[key] = ref
	return ref
}

func (b *cdxBuilder) add(c Obj) { b.components = append(b.components, c) }

func renderCycloneDX(r *renderSource) Obj {
	p := r.pred
	b := &cdxBuilder{toolRefs: map[string]string{}}
	product := O(p, "product")

	main := Obj{"type": "device", "bom-ref": "product", "name": S(product, "name")}
	setStr(main, "version", S(product, "revision"))
	setStr(main, "purl", S(product, "purl"))
	setStr(main, "cpe", S(product, "cpe"))
	main["manufacturer"] = cdxOrg(O(product, "manufacturer"))
	var mainProps [][2]string
	if lot := lotSubject(r.stmt); lot != nil {
		mainProps = append(mainProps, [2]string{"hbom:lot", strings.TrimPrefix(S(lot, "name"), "urn:hslsa:lot:")})
	}
	setList(main, "properties", cdxProps(mainProps))

	design := O(p, "design")
	for i, ip := range Objs(design, "ipBlocks") {
		c := Obj{"type": "library", "bom-ref": fmt.Sprintf("ip-%d", i+1), "name": S(ip, "name")}
		setStr(c, "version", S(ip, "version"))
		c["supplier"] = cdxOrg(O(ip, "supplier"))
		if l := S(ip, "license"); l != "" {
			c["licenses"] = []Obj{{"expression": l}}
		}
		if src := O(ip, "source"); src != nil {
			c["externalReferences"] = []Obj{cdxRef("vcs", src, "")}
		}
		props := [][2]string{{"hbom:ipKind", S(ip, "kind")}}
		props = append(props, orgExtra("hbom:supplier", O(ip, "supplier"))...)
		if e, ok := get(ip, "encrypted").(bool); ok {
			props = append(props, [2]string{"hbom:encrypted", fmt.Sprint(e)})
		}
		c["properties"] = cdxProps(props)
		b.add(c)
	}
	for i, src := range Objs(design, "rtlSources") {
		name := S(src, "path")
		if name == "" {
			name = S(src, "repo")
		}
		c := Obj{"type": "file", "bom-ref": fmt.Sprintf("rtl-%d", i+1), "name": name}
		setList(c, "hashes", cdxHashes(O(src, "digest")))
		c["externalReferences"] = []Obj{cdxRef("vcs", Obj{"uri": S(src, "repo"), "digest": O(src, "digest")}, "")}
		props := [][2]string{{"hbom:rtlSource", "true"}}
		if l := S(src, "language"); l != "" {
			props = append(props, [2]string{"hbom:language", l})
		}
		c["properties"] = cdxProps(props)
		b.add(c)
	}
	if pdk := O(design, "pdk"); pdk != nil {
		c := Obj{"type": "platform", "bom-ref": "pdk", "name": S(pdk, "name"), "version": S(pdk, "version")}
		if v := O(pdk, "vendor"); v != nil {
			c["supplier"] = cdxOrg(v)
		}
		setList(c, "hashes", cdxHashes(O(pdk, "digest")))
		props := [][2]string{{"hbom:pdk", "true"}}
		props = append(props, orgExtra("hbom:vendor", O(pdk, "vendor"))...)
		if g := S(pdk, "digest", "gitCommit"); g != "" {
			props = append(props, [2]string{"hbom:gitCommit", g})
		}
		c["properties"] = cdxProps(props)
		b.add(c)
	}
	if fl := O(design, "finalLayout"); fl != nil {
		c := Obj{"type": "file", "bom-ref": "final-layout", "name": refName(fl)}
		setStr(c, "mime-type", S(fl, "mediaType"))
		setList(c, "hashes", cdxHashes(O(fl, "digest")))
		c["externalReferences"] = []Obj{cdxRef("distribution", fl, "final layout")}
		c["properties"] = cdxProps([][2]string{{"hbom:finalLayout", "true"}})
		b.add(c)
	}
	for i, fw := range Objs(p, "firmware") {
		c := Obj{"type": "firmware", "bom-ref": fmt.Sprintf("fw-%d", i+1), "name": S(fw, "name")}
		setStr(c, "version", S(fw, "version"))
		setList(c, "hashes", cdxHashes(O(fw, "digest")))
		var refs []Obj
		if s := O(fw, "sbomRef"); s != nil {
			refs = append(refs, cdxRef("bom", s, "firmware SBOM"))
		}
		if v := O(fw, "referenceValuesRef"); v != nil {
			refs = append(refs, cdxRef("attestation", v, "firmware reference values (signed CoRIM)"))
		}
		setList(c, "externalReferences", refs)
		props := [][2]string{{"hbom:role", S(fw, "role")}}
		if s := S(fw, "storage"); s != "" {
			props = append(props, [2]string{"hbom:storage", s})
		}
		c["properties"] = cdxProps(props)
		b.add(c)
	}
	for i, part := range Objs(p, "parts") {
		c := Obj{"type": "device", "bom-ref": fmt.Sprintf("part-%d", i+1), "name": S(part, "mpn")}
		c["manufacturer"] = cdxOrg(O(part, "manufacturer"))
		if d := O(part, "distributor"); d != nil {
			c["supplier"] = cdxOrg(d)
		}
		var refs []Obj
		if h := O(part, "hbomRef"); h != nil {
			refs = append(refs, cdxRef("bom", h, "the part's signed HBOM"))
		}
		if d := O(part, "distributionRef"); d != nil {
			refs = append(refs, cdxRef("attestation", d, "signed distribution record for this lot"))
		}
		setList(c, "externalReferences", refs)
		props := [][2]string{{"hbom:mpn", S(part, "mpn")}}
		for _, rd := range Strs(part, "refDes") {
			props = append(props, [2]string{"hbom:refDes", rd})
		}
		for _, k := range []string{"dateCode", "lot"} {
			if v := S(part, k); v != "" {
				props = append(props, [2]string{"hbom:" + k, v})
			}
		}
		if a, ok := get(part, "authorized").(bool); ok {
			props = append(props, [2]string{"hbom:authorized", fmt.Sprint(a)})
		}
		props = append(props, orgExtra("hbom:manufacturer", O(part, "manufacturer"))...)
		props = append(props, orgExtra("hbom:distributor", O(part, "distributor"))...)
		c["properties"] = cdxProps(props)
		b.add(c)
	}

	var workflows []Obj
	if flow := Objs(design, "flow"); len(flow) > 0 {
		var tasks []Obj
		for i, step := range flow {
			name := S(step, "step")
			t := Obj{"bom-ref": fmt.Sprintf("design-%d", i+1), "uid": fmt.Sprintf("design-%d-%s", i+1, name), "name": name, "taskTypes": []string{cdxTaskType(name)}}
			var res []Obj
			for _, tool := range Objs(step, "tools") {
				res = append(res, Obj{"ref": b.tool(tool)})
			}
			setList(t, "resourceReferences", res)
			var outs []Obj
			for _, o := range Objs(step, "outputs") {
				outs = append(outs, Obj{"type": "artifact", "resource": Obj{"externalReference": cdxRef("distribution", o, "")}})
			}
			if pr := O(step, "provenanceRef"); pr != nil {
				outs = append(outs, Obj{"type": "attestation", "resource": Obj{"externalReference": cdxRef("attestation", pr, "design-flow record for this step")}})
			}
			setList(t, "outputs", outs)
			tasks = append(tasks, t)
		}
		workflows = append(workflows, Obj{"bom-ref": "design-flow", "uid": "design-flow", "name": "design flow", "taskTypes": []string{"build"}, "tasks": tasks})
	}
	if acts := mfgActions(p); len(acts) > 0 {
		var tasks []Obj
		for i, a := range acts {
			name := mfgName(a)
			typ := "build"
			if a.kind == "test" {
				typ = "test"
			}
			t := Obj{"bom-ref": fmt.Sprintf("mfg-%d", i+1), "uid": fmt.Sprintf("mfg-%d-%s", i+1, strings.ReplaceAll(name, " ", "-")), "name": name, "taskTypes": []string{typ}}
			if prog := O(a.block, "program"); prog != nil {
				t["resourceReferences"] = []Obj{{"ref": b.tool(prog)}}
			}
			if rec := mfgActionRecord(a); rec != nil {
				t["outputs"] = []Obj{{"type": "attestation", "resource": Obj{"externalReference": cdxRef("attestation", rec, "manufacturing-step record")}}}
			}
			fields := mfgFields(a)
			if a.kind == "fab" {
				fields = append(fields, waferLotFields(p)...)
			}
			t["properties"] = cdxProps(fields)
			tasks = append(tasks, t)
		}
		workflows = append(workflows, Obj{"bom-ref": "manufacturing", "uid": "manufacturing", "name": "manufacturing", "taskTypes": []string{"build", "test"}, "tasks": tasks})
	}

	var deps []Obj
	var refs []string
	for _, c := range b.components {
		refs = append(refs, S(c, "bom-ref"))
	}
	deps = append(deps, Obj{"ref": "product", "dependsOn": refs})
	for _, ref := range refs {
		deps = append(deps, Obj{"ref": ref})
	}

	meta := Obj{
		"timestamp": r.created,
		"tools": Obj{"components": []Obj{{
			"type": "application", "name": "hslsa", "version": RenderToolVersion,
			"externalReferences": []Obj{{"type": "vcs", "url": NS}},
		}}},
		"component":    main,
		"manufacturer": cdxOrg(O(product, "manufacturer")),
		"properties":   cdxProps(headFields(r)),
	}
	bom := Obj{
		"$schema":      "http://cyclonedx.org/schema/bom-1.6.schema.json",
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": "urn:uuid:" + r.uuid,
		"version":      1,
		"metadata":     meta,
		"dependencies": deps,
	}
	setList(bom, "components", b.components)
	if len(workflows) > 0 {
		f := Obj{"bom-ref": "formulation", "workflows": workflows}
		setList(f, "components", b.tools)
		bom["formulation"] = []Obj{f}
	}
	return bom
}

// cdxTaskType maps a design step name to a CycloneDX task type.
func cdxTaskType(step string) string {
	switch step {
	case "source-freeze":
		return "clone"
	case "simulation", "signoff":
		return "test"
	case "release":
		return "release"
	case "rom-merge":
		return "merge"
	case "other":
		return "other"
	}
	return "build"
}
