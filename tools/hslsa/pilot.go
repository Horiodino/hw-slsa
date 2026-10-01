package hslsa

// A buyer-run trust root for a pilot (roadmap phase 4, spec section
// "Buyer-run trust roots"). The buyer holds one root key and signs an
// enrollment record for each site key it accepts, after checking the key
// with the site itself: which role it signs for, which company and site
// holds it, how it is held, and for how long the buyer accepts it. A
// revocation record withdraws a key. The trust root the verifier reads is
// built from these records alone, at a stated time, so no supplier can add
// a key to it and an expired or revoked key drops out on the next build.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// EnrollmentType is the predicate of a buyer's site key enrollment.
	EnrollmentType = NS + "/site-enrollment/v0.1"
	// RevocationType is the predicate of a buyer's key revocation.
	RevocationType = NS + "/key-revocation/v0.1"
	// BuyerRootRole is the role of the buyer's root key in its own trust root.
	BuyerRootRole = "buyer-root"
)

// orgIDPattern is the HBOM schema's organization identifier form.
var orgIDPattern = regexp.MustCompile(`^(lei|duns|cage|uei|gln):[A-Za-z0-9]+$`)

// KeyCustody is how an enrolled key is held, as the site showed the buyer.
var KeyCustody = []string{"hsm", "file"}

// Enrollment is what a buyer accepts about one site key.
type Enrollment struct {
	Role    string
	OrgName string
	OrgID   string
	Site    string
	Country string
	Custody string
	// Accreditation is the scheme and certificate id of the site's
	// accreditation, as the buyer checked it; empty for none.
	Accreditation Accreditation
	NotBefore     time.Time
	NotAfter      time.Time
	Note          string
}

// Accreditation names a site's accreditation: the scheme (for example
// "DMEA Trusted Supplier" or "O-TTPS") and the certificate or listing id.
type Accreditation struct {
	Scheme, ID string
}

// keySubject names a public key by its keyid, with the sha256 of its
// SubjectPublicKeyInfo as the digest.
func keySubject(k Key) (Obj, error) {
	d, err := spkiDigest(k.Public)
	if err != nil {
		return nil, err
	}
	return rd("urn:hslsa:key:"+k.ID, d), nil
}

func readPublicKey(path string) (Key, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return Key{}, err
	}
	k, err := PublicKeyFromPEM(string(text))
	if err != nil {
		return Key{}, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

const timeFormat = "2006-01-02T15:04:05Z"

// Enroll signs the buyer's enrollment of the site key at pubPath.
func Enroll(buyerKey, pubPath string, e Enrollment, out string) error {
	switch {
	case e.Role == "" || e.Role == BuyerRootRole:
		return fmt.Errorf("enroll: a site key needs a role other than %s", BuyerRootRole)
	case e.OrgName == "" || e.Site == "":
		return fmt.Errorf("enroll: name the company and the site that hold the key")
	case !orgIDPattern.MatchString(e.OrgID):
		return fmt.Errorf("enroll: organization id %q is not lei:, duns:, cage:, uei: or gln: followed by the identifier", e.OrgID)
	case !contains(KeyCustody, e.Custody):
		return fmt.Errorf("enroll: key custody %q is not one of %s", e.Custody, strings.Join(KeyCustody, ", "))
	case !e.NotAfter.After(e.NotBefore):
		return fmt.Errorf("enroll: the enrollment ends before it starts")
	case (e.Accreditation.Scheme == "") != (e.Accreditation.ID == ""):
		return fmt.Errorf("enroll: an accreditation needs both its scheme and its id")
	}
	signer, err := LoadSigner(buyerKey)
	if err != nil {
		return err
	}
	k, err := readPublicKey(pubPath)
	if err != nil {
		return err
	}
	if k.ID == signer.Key.ID {
		return fmt.Errorf("enroll: the buyer's root key cannot be enrolled as a site key")
	}
	subject, err := keySubject(k)
	if err != nil {
		return err
	}
	site := Obj{"name": e.Site}
	if e.Country != "" {
		site["country"] = e.Country
	}
	pred := Obj{
		"role":         e.Role,
		"organization": Obj{"name": e.OrgName, "id": e.OrgID},
		"site":         site,
		"publicKey":    k.PEM,
		"keyCustody":   e.Custody,
		"validity":     Obj{"notBefore": e.NotBefore.UTC().Format(timeFormat), "notAfter": e.NotAfter.UTC().Format(timeFormat)},
		"enrolledOn":   Now(),
	}
	if e.Accreditation.Scheme != "" {
		pred["accreditation"] = Obj{"scheme": e.Accreditation.Scheme, "id": e.Accreditation.ID}
	}
	if e.Note != "" {
		pred["note"] = e.Note
	}
	stmt, err := statement([]Obj{subject}, EnrollmentType, pred)
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, out); err != nil {
		return err
	}
	fmt.Printf("enrolled %s for %s at %s (%s) until %s\n", k.ID[:16], e.Role, e.Site, e.OrgName, e.NotAfter.UTC().Format(timeFormat))
	return nil
}

// Revoke signs the buyer's revocation of the key at pubPath.
func Revoke(buyerKey, pubPath, reason, out string) error {
	if reason == "" {
		return fmt.Errorf("revoke: give the reason")
	}
	signer, err := LoadSigner(buyerKey)
	if err != nil {
		return err
	}
	k, err := readPublicKey(pubPath)
	if err != nil {
		return err
	}
	subject, err := keySubject(k)
	if err != nil {
		return err
	}
	stmt, err := statement([]Obj{subject}, RevocationType, Obj{"publicKey": k.PEM, "reason": reason, "revokedOn": Now()})
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, out); err != nil {
		return err
	}
	fmt.Printf("revoked %s: %s\n", k.ID[:16], reason)
	return nil
}

// recordKey is the key a buyer record names: its PEM must match its subject.
func recordKey(stmt Obj, name string) (Key, error) {
	k, err := PublicKeyFromPEM(S(stmt, "predicate", "publicKey"))
	if err != nil {
		return Key{}, failf("%s: public key: %v", name, err)
	}
	want, err := keySubject(k)
	if err != nil {
		return Key{}, err
	}
	subs := Objs(stmt, "subject")
	if len(subs) != 1 || !jsonEqual(subs[0], want) {
		return Key{}, failf("%s: subject does not name the key it carries", name)
	}
	return k, nil
}

func parseTime(s, what string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, failf("%s: not an RFC 3339 time: %q", what, s)
	}
	return t, nil
}

// BuildPilotTrustRoot checks every record in dir against the buyer's root
// key and writes the trust root valid at time at: every enrolled key whose
// enrollment covers at and that no revocation names, by role. Any file in
// dir that the buyer did not sign, or that is not an enrollment or a
// revocation, stops the build: the directory is the buyer's own. One key
// enrolled for two roles or two companies stops it too.
func BuildPilotTrustRoot(buyerPub, dir string, at time.Time, out string) (Obj, error) {
	root, err := readPublicKey(buyerPub)
	if err != nil {
		return nil, err
	}
	buyer := &TrustRoot{Roles: map[string][]Key{BuyerRootRole: {root}}}
	files, err := filepath.Glob(filepath.Join(dir, "*.intoto.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no enrollment records", dir)
	}
	type entry struct {
		key  Key
		stmt Obj
		file string
		rd   Obj
	}
	var enrolled []entry
	revoked := map[string]string{}
	for _, f := range files {
		name := filepath.Base(f)
		raw, err := DecodeEnvelope(f)
		if err != nil {
			return nil, err
		}
		pt := S(raw, "predicateType")
		if pt != EnrollmentType && pt != RevocationType {
			return nil, failf("%s: not an enrollment or a revocation (%s)", name, pt)
		}
		stmt, err := buyer.Open(f, BuyerRootRole, pt)
		if err != nil {
			return nil, err
		}
		k, err := recordKey(stmt, name)
		if err != nil {
			return nil, err
		}
		if pt == RevocationType {
			revoked[k.ID] = S(stmt, "predicate", "reason")
			continue
		}
		d, err := sha256File(f)
		if err != nil {
			return nil, err
		}
		enrolled = append(enrolled, entry{k, stmt, name, rd(name, d)})
	}

	roles := Obj{}
	var accepted, excluded []any
	var until time.Time
	keyRole, keyOrg := map[string]string{}, map[string]string{}
	for _, e := range enrolled {
		p := O(e.stmt, "predicate")
		role, org := S(p, "role"), S(p, "organization", "id")
		if r, ok := keyRole[e.key.ID]; ok && r != role {
			return nil, failf("%s: key %s is enrolled for both %s and %s; enroll one key per role", e.file, e.key.ID[:16], r, role)
		}
		if o, ok := keyOrg[e.key.ID]; ok && o != org {
			return nil, failf("%s: key %s is enrolled for two companies, %s and %s", e.file, e.key.ID[:16], o, org)
		}
		keyRole[e.key.ID], keyOrg[e.key.ID] = role, org
		if role == "" || role == BuyerRootRole || !orgIDPattern.MatchString(org) {
			return nil, failf("%s: enrollment needs a site role and a valid organization id", e.file)
		}
		nb, err := parseTime(S(p, "validity", "notBefore"), e.file+" notBefore")
		if err != nil {
			return nil, err
		}
		na, err := parseTime(S(p, "validity", "notAfter"), e.file+" notAfter")
		if err != nil {
			return nil, err
		}
		desc := Obj{
			"keyid": e.key.ID, "role": role, "organization": O(p, "organization"), "site": O(p, "site"),
			"keyCustody": S(p, "keyCustody"), "notAfter": S(p, "validity", "notAfter"), "record": e.rd,
		}
		if a := O(p, "accreditation"); a != nil {
			desc["accreditation"] = a
		}
		reason := ""
		switch {
		case revoked[e.key.ID] != "":
			reason = "revoked: " + revoked[e.key.ID]
		case at.Before(nb):
			reason = "not valid until " + S(p, "validity", "notBefore")
		case !at.Before(na):
			reason = "expired " + S(p, "validity", "notAfter")
		}
		who := fmt.Sprintf("%s %s (%s, %s)", role, e.key.ID[:16], S(p, "site", "name"), S(p, "organization", "name"))
		if reason != "" {
			desc["reason"] = reason
			excluded = append(excluded, desc)
			fmt.Printf("excluded %s: %s\n", who, reason)
			continue
		}
		list, _ := roles[role].([]any)
		roles[role] = append(list, e.key.PEM)
		accepted = append(accepted, desc)
		if until.IsZero() || na.Before(until) {
			until = na
		}
		fmt.Printf("trusted  %s\n", who)
	}
	if len(accepted) == 0 {
		return nil, fmt.Errorf("no enrolled key is valid at %s", at.UTC().Format(timeFormat))
	}
	tr := Obj{
		"roles":       roles,
		"buyerRoot":   root.ID,
		"builtAt":     at.UTC().Format(timeFormat),
		"validUntil":  until.UTC().Format(timeFormat),
		"enrollments": accepted,
	}
	if excluded != nil {
		tr["excluded"] = excluded
	}
	return tr, WriteJSON(out, tr)
}

// checkTrustRootValid refuses a trust root past its validUntil, which a
// buyer-run trust root carries: rebuild it from the enrollments instead.
func checkTrustRootValid(path string, data Obj) error {
	until := S(data, "validUntil")
	if until == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, until)
	if err != nil {
		return fmt.Errorf("%s: validUntil: %w", path, err)
	}
	if !time.Now().Before(t) {
		return failf("%s: trust root expired %s, when its first enrollment ended; rebuild it from the enrollments", filepath.Base(path), until)
	}
	return nil
}
