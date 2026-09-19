package hslsa

// Selective disclosure (spec section "Selective disclosure"): a producer
// withholds a field by removing it before signing and listing a salted digest
// of it in the record. The disclosure, which carries the salt, the field's
// JSON Pointer and its value, goes only to whoever may see the value (an
// auditor). One signed record then serves every audience: a party without the
// disclosure sees the digest, a party with it can prove the value was signed.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// saltBytes is the salt length for withheld fields and files: 128 bits.
const saltBytes = 16

// newSalt is a fresh random salt, base64url without padding.
func newSalt() (string, error) {
	b := make([]byte, saltBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// saltOK reports whether s decodes to a salt of at least 128 bits.
func saltOK(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) >= saltBytes
}

// Withholding says which fields and files a producer withholds, as in
// e2e/picorv32/withhold.json: "fields" maps a record (a manufacturing step
// name, or "hbom") to JSON Pointers into its predicate, and "saltFiles" names
// the data files that get a salt so their digests cannot be guessed.
type Withholding struct {
	Fields    map[string][]string
	SaltFiles []string
}

// LoadWithholding reads a withholding file; an empty path means nothing is withheld.
func LoadWithholding(path string) (*Withholding, error) {
	if path == "" {
		return nil, nil
	}
	v, err := ReadObj(path)
	if err != nil {
		return nil, err
	}
	w := &Withholding{Fields: map[string][]string{}, SaltFiles: Strs(v, "saltFiles")}
	for record := range O(v, "fields") {
		w.Fields[record] = Strs(v, "fields", record)
	}
	return w, nil
}

func (w *Withholding) fields(record string) []string {
	if w == nil {
		return nil
	}
	return w.Fields[record]
}

func (w *Withholding) salts(file string) bool { return w != nil && contains(w.SaltFiles, file) }

// withheldList is where a predicate type lists its withheld fields.
func withheldList(predicateType string) []string {
	switch predicateType {
	case MfgStep:
		return []string{"hwMfg", "confidential"}
	case HBOMType:
		return []string{"redactions"}
	}
	return nil
}

// protectedFields are the fields that tie the chain together, so anyone
// holding the records can still check signatures, links and gate results. A
// withheld path may not be one of them, inside one, or above one.
var protectedFields = map[string][]string{
	MfgStep: {
		"/buildDefinition/buildType", "/buildDefinition/resolvedDependencies",
		"/runDetails/builder", "/hwMfg/step", "/hwMfg/designRef", "/hwMfg/checks",
	},
	HBOMType: {"/hbomVersion", "/product"},
}

// requiredBlocks must stay in the record, but their members may be withheld.
var requiredBlocks = map[string][]string{
	MfgStep: {"/buildDefinition/externalParameters"},
}

// parsePointer splits an RFC 6901 JSON Pointer into its reference tokens.
func parsePointer(p string) ([]string, error) {
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("JSON Pointer %q does not start with /", p)
	}
	tokens := strings.Split(p[1:], "/")
	for i, t := range tokens {
		if t == "" {
			return nil, fmt.Errorf("JSON Pointer %q has an empty token", p)
		}
		tokens[i] = strings.NewReplacer("~1", "/", "~0", "~").Replace(t)
	}
	return tokens, nil
}

// isPrefix reports whether a is a prefix of b, token by token.
func isPrefix(a, b []string) bool {
	if len(a) > len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parentOf resolves every token but the last, which must name a member of an
// object. Array indices are allowed on the way.
func parentOf(root any, tokens []string) (Obj, error) {
	v := root
	for _, t := range tokens[:len(tokens)-1] {
		switch x := v.(type) {
		case map[string]any:
			next, ok := x[t]
			if !ok {
				return nil, fmt.Errorf("no member %q", t)
			}
			v = next
		case []any:
			i, err := strconv.Atoi(t)
			if err != nil || i < 0 || i >= len(x) || strconv.Itoa(i) != t {
				return nil, fmt.Errorf("no array element %q", t)
			}
			v = x[i]
		default:
			return nil, fmt.Errorf("%q is not inside an object or array", t)
		}
	}
	parent, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the last token must name an object member")
	}
	return parent, nil
}

// checkPaths parses the paths to withhold for a predicate type: no path may
// be protected, repeated, or inside another.
func checkPaths(predicateType string, paths []string) ([][]string, error) {
	var parsed [][]string
	for _, p := range paths {
		tokens, err := parsePointer(p)
		if err != nil {
			return nil, err
		}
		if list := withheldList(predicateType); list != nil && (isPrefix(list, tokens) || isPrefix(tokens, list)) {
			return nil, fmt.Errorf("%s cannot be withheld: it is the list of withheld fields", p)
		}
		for _, q := range protectedFields[predicateType] {
			pt, _ := parsePointer(q)
			if isPrefix(pt, tokens) || isPrefix(tokens, pt) {
				return nil, fmt.Errorf("%s cannot be withheld: the chain needs %s", p, q)
			}
		}
		for _, q := range requiredBlocks[predicateType] {
			if pt, _ := parsePointer(q); isPrefix(tokens, pt) {
				return nil, fmt.Errorf("%s cannot be withheld: the record needs %s, though its members may be withheld", p, q)
			}
		}
		for i, other := range parsed {
			if isPrefix(other, tokens) || isPrefix(tokens, other) {
				return nil, fmt.Errorf("%s overlaps %s", p, paths[i])
			}
		}
		parsed = append(parsed, tokens)
	}
	return parsed, nil
}

// withhold returns the predicate with each path removed and its salted digest
// listed, and the disclosures in the order of paths.
func withhold(predicate Obj, predicateType string, paths []string) (Obj, []string, error) {
	if len(paths) == 0 {
		return predicate, nil, nil
	}
	listAt := withheldList(predicateType)
	if listAt == nil {
		return nil, nil, fmt.Errorf("predicate type %s has no list of withheld fields", predicateType)
	}
	parsed, err := checkPaths(predicateType, paths)
	if err != nil {
		return nil, nil, err
	}
	// Work on decoded JSON, so arrays built as []Obj can be walked like any other.
	predicate = normalize(predicate).(map[string]any)
	var disclosures []string
	var entries []any
	for i, tokens := range parsed {
		parent, err := parentOf(predicate, tokens)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", paths[i], err)
		}
		last := tokens[len(tokens)-1]
		value, ok := parent[last]
		if !ok {
			return nil, nil, fmt.Errorf("%s: no member %q", paths[i], last)
		}
		salt, err := newSalt()
		if err != nil {
			return nil, nil, err
		}
		d := base64.RawURLEncoding.EncodeToString(compactJSON([]any{salt, paths[i], value}))
		disclosures = append(disclosures, d)
		entries = append(entries, Obj{"path": paths[i], "saltedDigest": Obj{"sha256": sha256Bytes([]byte(d))}})
		delete(parent, last)
	}
	holder, err := parentOf(predicate, listAt)
	if err != nil {
		return nil, nil, fmt.Errorf("predicate has no %s: %w", strings.Join(listAt, "."), err)
	}
	existing, _ := holder[listAt[len(listAt)-1]].([]any)
	holder[listAt[len(listAt)-1]] = append(existing, entries...)
	return predicate, disclosures, nil
}

// disclosurePath is where a bundle keeps the disclosures for the envelope at
// path: disclosures/<name>.disclosures.json beside the att directory.
func disclosurePath(envelope string) string {
	name := strings.TrimSuffix(filepath.Base(envelope), ".intoto.json")
	return filepath.Join(filepath.Dir(filepath.Dir(envelope)), "disclosures", name+".disclosures.json")
}

// writeDisclosures stores an envelope's disclosures, or removes a stale file
// when it withholds nothing.
func writeDisclosures(envelope string, disclosures []string) error {
	path := disclosurePath(envelope)
	if len(disclosures) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return WriteJSON(path, Obj{"envelope": filepath.Base(envelope), "disclosures": anyStrings(disclosures)})
}

// Withheld lists the paths a statement withholds, with their salted digests.
func Withheld(stmt Obj) []Obj {
	list := withheldList(S(stmt, "predicateType"))
	if list == nil {
		return nil
	}
	return Objs(get(stmt, append([]string{"predicate"}, list...)...))
}

// reveal puts every withheld field of a verified statement back from its
// disclosures, and fails when one is missing, forged or would overwrite a
// signed value. A statement that withholds nothing is returned as it is.
func reveal(envelope string, stmt Obj) (Obj, error) {
	name := filepath.Base(envelope)
	entries := Withheld(stmt)
	if len(entries) == 0 {
		return stmt, nil
	}
	predicateType := S(stmt, "predicateType")
	byDigest := map[string]Obj{}
	var paths []string
	for _, e := range entries {
		d := S(e, "saltedDigest", "sha256")
		if S(e, "path") == "" || d == "" {
			return nil, failf("%s: a withheld field has no path or salted digest", name)
		}
		if _, dup := byDigest[d]; dup {
			return nil, failf("%s: two withheld fields share a salted digest", name)
		}
		byDigest[d] = e
		paths = append(paths, S(e, "path"))
	}
	if _, err := checkPaths(predicateType, paths); err != nil {
		return nil, failf("%s: %v", name, err)
	}
	file, err := ReadObj(disclosurePath(envelope))
	if err != nil {
		return nil, failf("%s: %s is withheld and no disclosure was given", name, paths[0])
	}
	predicate := O(stmt, "predicate")
	values := map[string]any{}
	for _, d := range Strs(file, "disclosures") {
		e, ok := byDigest[sha256Bytes([]byte(d))]
		if !ok {
			return nil, failf("%s: a disclosure matches no withheld field", name)
		}
		raw, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			return nil, failf("%s: disclosure for %s is not base64url", name, S(e, "path"))
		}
		v, err := decodeJSON(raw)
		arr, _ := v.([]any)
		if err != nil || len(arr) != 3 {
			return nil, failf("%s: disclosure for %s is not [salt, path, value]", name, S(e, "path"))
		}
		salt, _ := arr[0].(string)
		path, _ := arr[1].(string)
		if !saltOK(salt) {
			return nil, failf("%s: disclosure for %s has a salt shorter than 128 bits", name, S(e, "path"))
		}
		if path != S(e, "path") {
			return nil, failf("%s: disclosure for %s is listed as %s", name, path, S(e, "path"))
		}
		values[path] = arr[2]
	}
	for _, p := range paths {
		value, ok := values[p]
		if !ok {
			return nil, failf("%s: %s is withheld and no disclosure was given", name, p)
		}
		tokens, _ := parsePointer(p)
		parent, err := parentOf(predicate, tokens)
		if err != nil {
			return nil, failf("%s: withheld %s: %v", name, p, err)
		}
		last := tokens[len(tokens)-1]
		if _, present := parent[last]; present {
			return nil, failf("%s: %s is both withheld and present", name, p)
		}
		parent[last] = value
	}
	return stmt, nil
}
