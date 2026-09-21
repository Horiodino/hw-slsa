package hslsa

// PKCS#11 URIs (RFC 7512) name a key held in an HSM. The parsing lives here,
// outside the cgo build, so a tool built without cgo still says why it cannot
// open the key.

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// PKCS11RefSuffix is the file that stands in for <role>.key.pem when the
// role's key is in an HSM: it holds the key's PKCS#11 URI and no secret.
const PKCS11RefSuffix = ".pkcs11"

// Environment variables for what a PKCS#11 URI leaves out. The PIN is best
// kept out of the URI, since the URI is written to <role>.pkcs11.
const (
	PKCS11ModuleEnv = "HSLSA_PKCS11_MODULE"
	PKCS11PINEnv    = "HSLSA_PKCS11_PIN"
)

type pkcs11URI struct {
	token, serial, object string
	id                    []byte
	slot                  *uint
	module, pin           string
}

func isPKCS11URI(s string) bool { return strings.HasPrefix(s, "pkcs11:") }

// parsePKCS11URI reads the path attributes token, serial, slot-id, object, id
// and type (which must be private), and the query attributes module-path,
// pin-value and pin-source (a file:// URI or a path). The module falls back to
// HSLSA_PKCS11_MODULE and the PIN to HSLSA_PKCS11_PIN.
func parsePKCS11URI(uri string) (*pkcs11URI, error) {
	body, ok := strings.CutPrefix(uri, "pkcs11:")
	if !ok {
		return nil, fmt.Errorf("not a PKCS#11 URI: %q", uri)
	}
	path, query, _ := strings.Cut(body, "?")
	u := &pkcs11URI{}
	attr := func(part string) (string, string, error) {
		k, v, _ := strings.Cut(part, "=")
		val, err := url.PathUnescape(v)
		if err != nil {
			return "", "", fmt.Errorf("PKCS#11 URI attribute %s: %w", k, err)
		}
		return k, val, nil
	}
	for _, part := range strings.Split(path, ";") {
		if part == "" {
			continue
		}
		k, v, err := attr(part)
		if err != nil {
			return nil, err
		}
		switch k {
		case "token":
			u.token = v
		case "serial":
			u.serial = v
		case "object":
			u.object = v
		case "id":
			u.id = []byte(v)
		case "slot-id":
			n, err := strconv.ParseUint(v, 10, 0)
			if err != nil {
				return nil, fmt.Errorf("PKCS#11 URI slot-id %q: %w", v, err)
			}
			slot := uint(n)
			u.slot = &slot
		case "type":
			if v != "private" {
				return nil, fmt.Errorf("PKCS#11 URI names a %s object; a signing key is type=private", v)
			}
		}
	}
	var pinSource string
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			continue
		}
		k, v, err := attr(part)
		if err != nil {
			return nil, err
		}
		switch k {
		case "module-path":
			u.module = v
		case "pin-value":
			u.pin = v
		case "pin-source":
			pinSource = v
		}
	}
	if u.object == "" && u.id == nil {
		return nil, fmt.Errorf("PKCS#11 URI %s names no key: give object= or id=", uri)
	}
	if u.module == "" {
		u.module = os.Getenv(PKCS11ModuleEnv)
	}
	if u.module == "" {
		return nil, fmt.Errorf("PKCS#11 URI %s has no module-path and %s is not set", uri, PKCS11ModuleEnv)
	}
	if u.pin == "" && pinSource != "" {
		data, err := os.ReadFile(strings.TrimPrefix(pinSource, "file://"))
		if err != nil {
			return nil, fmt.Errorf("PKCS#11 pin-source: %w", err)
		}
		u.pin = strings.TrimRight(string(data), "\r\n")
	}
	if u.pin == "" {
		u.pin = os.Getenv(PKCS11PINEnv)
	}
	return u, nil
}

// pkcs11Escape percent-encodes a URI attribute value, keeping what RFC 7512 allows unescaped.
func pkcs11Escape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~/:", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// PKCS11KeyURI names the private key labelled object on the token labelled
// token, loaded through module. It carries no PIN.
func PKCS11KeyURI(module, token, object string) string {
	return "pkcs11:token=" + pkcs11Escape(token) + ";object=" + pkcs11Escape(object) + ";type=private?module-path=" + pkcs11Escape(module)
}
