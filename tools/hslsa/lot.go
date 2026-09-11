package hslsa

import (
	"errors"
	"os"
	"sort"
	"strings"
)

// The shipped lot digest (spec section "Lot digest").

var errDuplicateUnits = errors.New("duplicate unit identifiers")

// CanonicalUnits sorts the unit ids as byte strings, joins them with newlines
// and adds one trailing newline. Blank ids are ignored; duplicates are an error.
func CanonicalUnits(ids []string) ([]byte, error) {
	seen := map[string]bool{}
	var out []string
	count := 0
	for _, u := range ids {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		count++
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if len(out) != count {
		return nil, errDuplicateUnits
	}
	sort.Strings(out)
	return []byte(strings.Join(out, "\n") + "\n"), nil
}

// LotDigest is the sha256 of the canonical unit list.
func LotDigest(ids []string) (string, error) {
	c, err := CanonicalUnits(ids)
	if err != nil {
		return "", err
	}
	return sha256Bytes(c), nil
}

// ReadUnits returns the non-blank lines of a unit list.
func ReadUnits(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range splitLines(string(data)) {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func writeUnits(path string, ids []string) error {
	c, err := CanonicalUnits(ids)
	if err != nil {
		return err
	}
	return os.WriteFile(path, c, 0o644)
}

// splitLines splits on \n, \r\n and \r, without a final empty line.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func setOf(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, x := range list {
		m[x] = true
	}
	return m
}

func sameSet(a, b []string) bool {
	sa, sb := setOf(a), setOf(b)
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if !sb[k] {
			return false
		}
	}
	return true
}

// minus is sorted(set(a) - set(b)).
func minus(a, b []string) []string {
	sb := setOf(b)
	var out []string
	for k := range setOf(a) {
		if !sb[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sortedCopy(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func anyStrings(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}
