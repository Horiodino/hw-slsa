// Package formats embeds the official JSON Schemas of the formats the HBOM is
// rendered in, byte for byte as published, so hslsa render checks every
// document it writes without network access. See README.md for where each
// file comes from.
package formats

import _ "embed"

// CycloneDX 1.6 (ECMA-424), from tag 1.6.1 of CycloneDX/specification. The
// BOM schema refers to the other two by these IDs.
var (
	//go:embed cyclonedx-1.6/bom-1.6.schema.json
	CycloneDXSchema []byte
	//go:embed cyclonedx-1.6/spdx.schema.json
	CycloneDXLicenseSchema []byte
	//go:embed cyclonedx-1.6/jsf-0.82.schema.json
	CycloneDXSignatureSchema []byte
)

const (
	CycloneDXSchemaID          = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	CycloneDXLicenseSchemaID   = "http://cyclonedx.org/schema/spdx.schema.json"
	CycloneDXSignatureSchemaID = "http://cyclonedx.org/schema/jsf-0.82.schema.json"
)

// SPDX 3.1 release candidate 1, the JSON Schema generated from the model.
//
//go:embed spdx-3.1-rc1/schema.json
var SPDXSchema []byte

const (
	// SPDXSchemaID is a local name: the published schema has no $id.
	SPDXSchemaID = "https://spdx.github.io/spdx-spec/3.1-RC1/rdf/schema.json"
	// SPDXContext is the JSON-LD context the schema requires as @context.
	SPDXContext = "https://spdx.github.io/spdx-spec/v3.1-RC1/rdf/spdx-context.jsonld"
)
