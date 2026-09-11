package hslsa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// Obj is a JSON object. Records are handled as generic JSON, as the Python
// reference tool did, so a verifier or a test can re-sign a record it did not
// write without dropping fields it does not know.
type Obj = map[string]any

// get walks nested objects by key and returns nil when any step is missing.
func get(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// O returns the object at keys, or nil.
func O(v any, keys ...string) Obj {
	m, _ := get(v, keys...).(map[string]any)
	return m
}

// S returns the string at keys, or "".
func S(v any, keys ...string) string {
	s, _ := get(v, keys...).(string)
	return s
}

// A returns the array at keys as []any, or nil.
func A(v any, keys ...string) []any {
	switch a := get(v, keys...).(type) {
	case []any:
		return a
	case []Obj:
		out := make([]any, len(a))
		for i, x := range a {
			out[i] = x
		}
		return out
	case []string:
		out := make([]any, len(a))
		for i, x := range a {
			out[i] = x
		}
		return out
	}
	return nil
}

// Objs returns the objects in the array at keys, skipping anything else.
func Objs(v any, keys ...string) []Obj {
	var out []Obj
	for _, x := range A(v, keys...) {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// Strs returns the strings in the array at keys.
func Strs(v any, keys ...string) []string {
	var out []string
	for _, x := range A(v, keys...) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Has reports whether an object has key.
func Has(v any, key string) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, ok = m[key]
	return ok
}

// Int returns the integer at keys. Booleans count as 0 and 1, as in Python.
func Int(v any, keys ...string) (int64, bool) {
	switch n := get(v, keys...).(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		if f, err := n.Float64(); err == nil && f == float64(int64(f)) {
			return int64(f), true
		}
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// Truthy is Python's truth test for a decoded JSON value.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, err := x.Float64()
		return err != nil || f != 0
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// encode writes v as JSON with sorted object keys and without HTML escaping.
func encode(v any, indent bool) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// compactJSON is json.dumps(v, sort_keys=True, separators=(",", ":")).
func compactJSON(v any) []byte {
	b, err := encode(v, false)
	if err != nil {
		panic(fmt.Sprintf("hslsa: value is not JSON: %v", err))
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

// jsonEqual compares two JSON values by their canonical encoding.
func jsonEqual(a, b any) bool {
	return bytes.Equal(compactJSON(a), compactJSON(b))
}

// normalize round-trips v through JSON, so it holds only decoded types.
func normalize(v any) any {
	out, err := decodeJSON(compactJSON(v))
	if err != nil {
		panic(err)
	}
	return out
}

func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after JSON value")
	}
	return v, nil
}

// ReadJSON reads a JSON file, keeping numbers exactly as written.
func ReadJSON(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := decodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

// ReadObj reads a JSON file that holds an object.
func ReadObj(path string) (Obj, error) {
	v, err := ReadJSON(path)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: not a JSON object", path)
	}
	return m, nil
}

// readLenientObj reads a JSON object that may hold the bare NaN, Infinity
// and -Infinity tokens Python's json module writes. They become the strings
// "nan", "inf" and "-inf", which is how records carry them.
func readLenientObj(path string) (Obj, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := decodeJSON(replaceNonFinite(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: not a JSON object", path)
	}
	return m, nil
}

func replaceNonFinite(data []byte) []byte {
	var out bytes.Buffer
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out.WriteByte(c)
			continue
		}
		replaced := false
		for _, tok := range [][2]string{{"-Infinity", `"-inf"`}, {"Infinity", `"inf"`}, {"NaN", `"nan"`}} {
			if bytes.HasPrefix(data[i:], []byte(tok[0])) {
				out.WriteString(tok[1])
				i += len(tok[0]) - 1
				replaced = true
				break
			}
		}
		if !replaced {
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

// WriteJSON writes v with two-space indentation, sorted keys and a trailing
// newline, creating the parent directory.
func WriteJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := encode(v, true)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// num formats a JSON number or other scalar the way Python's str() would for
// the values records hold.
func num(v any) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case nil:
		return "None"
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	}
	return fmt.Sprint(v)
}
