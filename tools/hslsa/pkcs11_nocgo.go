//go:build !cgo

package hslsa

import "errors"

var errNoPKCS11 = errors.New("this hslsa was built without cgo, which PKCS#11 needs; rebuild with CGO_ENABLED=1")

func loadPKCS11Signer(uri string) (*Signer, error) {
	if _, err := parsePKCS11URI(uri); err != nil {
		return nil, err
	}
	return nil, errNoPKCS11
}

// HSMKeygen needs cgo; see pkcs11.go.
func HSMKeygen(module, token, pin, outDir, role string) (*Signer, error) {
	return nil, errNoPKCS11
}
