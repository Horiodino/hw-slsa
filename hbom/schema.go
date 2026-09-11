// Package hbom embeds the HBOM predicate schema, so tools validate against
// the committed schema without needing the repository checked out.
package hbom

import _ "embed"

// Schema is hbom-predicate-v0.1.schema.json, byte for byte.
//
//go:embed hbom-predicate-v0.1.schema.json
var Schema []byte

// SchemaID is the schema's $id.
const SchemaID = "https://github.com/Horiodino/hw-slsa/hbom/v0.1/schema.json"
