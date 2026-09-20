// Command hslsa is the reference tool for the Hardware Supply Chain Security
// Framework: hslsa <command> [flags]. Run hslsa help for the commands.
package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Horiodino/hw-slsa/tools/hslsa"
)

type command struct {
	help string
	run  func(args []string) error
}

var commands = map[string]command{
	"keygen":        {"generate ECDSA P-256 keys, one per role", keygen},
	"pubkey":        {"write the public key for an existing private key", pubkey},
	"keyid":         {"print the DSSE keyid for a public or private key", keyid},
	"trust-root":    {"build a trust root from <role>.pub.pem files", trustRoot},
	"design":        {"run and attest one design flow step", design},
	"mfg":           {"emit signed F1 to F4 records for the scenario lot", mfg},
	"hbom":          {"build, validate and sign the HBOM", hbomCmd},
	"verify":        {"tapeout and lot receipt checks, then VSAs", verify},
	"escrow":        {"verifier escrow: the auditor's full check and VSAs, or the buyer's check of them", escrow},
	"leaks":         {"measure what the signed records and the escrow VSAs reveal", leaks},
	"openlane":      {"OpenLane 2 flow with a signed record per step", openlane},
	"caliptra":      {"the Caliptra example (e2e/caliptra)", caliptra},
	"board":         {"board-level example: shipments, A1 and board HBOM, or the buyer's board check", board},
	"lot-digest":    {"compute the lot digest of a unit list", lotDigest},
	"subject":       {"print the name and sha256 of an envelope's first subject", subject},
	"validate-hbom": {"validate HBOM statements or envelopes against the schema", validateHBOM},
	"corim":         {"show a signed CoRIM, or appraise DICE certificates against it", corimCmd},
	"safe":          {"sign, show or check an OCP S.A.F.E. short-form report", safeCmd},
}

// usageError is a command line mistake: exit status 2, like argparse.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hslsa <command> [flags]\n\ncommands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", n, commands[n].help)
	}
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		if len(os.Args) < 2 {
			os.Exit(2)
		}
		return
	}
	cmd, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "hslsa: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	err := cmd.run(os.Args[2:])
	var ue usageError
	switch {
	case err == nil:
	case errors.As(err, &ue):
		fmt.Fprintf(os.Stderr, "hslsa %s: %s\n", os.Args[1], ue.msg)
		os.Exit(2)
	case errors.Is(err, flag.ErrHelp):
		os.Exit(0)
	case hslsa.IsVerificationError(err):
		fmt.Fprintf(os.Stderr, "FAILED: %s\n", err)
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// flags is a flag set with required-flag checking.
type flags struct {
	*flag.FlagSet
	values   map[string]*string
	required []string
}

func newFlags(name string) *flags {
	fs := flag.NewFlagSet("hslsa "+name, flag.ContinueOnError)
	return &flags{FlagSet: fs, values: map[string]*string{}}
}

func (f *flags) str(name, usage string, required bool) *string {
	v := f.String(name, "", usage)
	f.values[name] = v
	if required {
		f.required = append(f.required, name)
	}
	return v
}

func (f *flags) parse(args []string) error {
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err.Error()}
	}
	var missing []string
	for _, r := range f.required {
		if *f.values[r] == "" {
			missing = append(missing, "--"+r)
		}
	}
	if len(missing) > 0 {
		return usageError{"the following arguments are required: " + strings.Join(missing, ", ")}
	}
	return nil
}

func need(v *string, name, when string) error {
	if *v == "" {
		return usageError{fmt.Sprintf("%s needs --%s", when, name)}
	}
	return nil
}

// action takes the positional action before the flags, checking it against choices.
func action(args []string, choices ...string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, usageError{"expected one of: " + strings.Join(choices, ", ")}
	}
	for _, c := range choices {
		if args[0] == c {
			return c, args[1:], nil
		}
	}
	return "", nil, usageError{fmt.Sprintf("invalid choice %q (choose from %s)", args[0], strings.Join(choices, ", "))}
}

func keygen(args []string) error {
	f := newFlags("keygen")
	out := f.str("out", "directory for <role>.key.pem and <role>.pub.pem", true)
	if err := f.parse(args); err != nil {
		return err
	}
	if f.NArg() == 0 {
		return usageError{"at least one role is required"}
	}
	for _, role := range f.Args() {
		if _, err := hslsa.Keygen(*out, role); err != nil {
			return err
		}
	}
	return nil
}

func pubkey(args []string) error {
	f := newFlags("pubkey")
	key := f.str("key", "private key", true)
	out := f.str("out", "public key to write", true)
	if err := f.parse(args); err != nil {
		return err
	}
	s, err := hslsa.LoadSigner(*key)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, []byte(s.Key.PEM), 0o644)
}

func keyid(args []string) error {
	f := newFlags("keyid")
	key := f.str("key", "public or private key", true)
	if err := f.parse(args); err != nil {
		return err
	}
	text, err := os.ReadFile(*key)
	if err != nil {
		return err
	}
	var k hslsa.Key
	if strings.Contains(string(text), "PRIVATE") {
		s, err := hslsa.LoadSigner(*key)
		if err != nil {
			return err
		}
		k = s.Key
	} else if k, err = hslsa.PublicKeyFromPEM(string(text)); err != nil {
		return err
	}
	fmt.Println(k.ID)
	return nil
}

func trustRoot(args []string) error {
	f := newFlags("trust-root")
	keys := f.str("keys", "directory of <role>.pub.pem", true)
	out := f.str("out", "trust root to write", true)
	if err := f.parse(args); err != nil {
		return err
	}
	return hslsa.BuildTrustRoot(*keys, *out)
}

func design(args []string) error {
	step, rest, err := action(args, "ip-release", "source-tag", "review", "source-freeze", "simulation", "synthesis", "release")
	if err != nil {
		return err
	}
	f := newFlags("design " + step)
	bundle := f.str("bundle", "", true)
	lock := f.str("lock", "", true)
	key := f.str("key", "", true)
	cache := f.str("cache", "", false)
	trust := f.str("trust-root", "", false)
	policy := f.str("policy", "", false)
	if err := f.parse(rest); err != nil {
		return err
	}
	if *cache == "" {
		*cache = ".hslsa-cache"
	}
	switch step {
	case "ip-release":
		return hslsa.IPRelease(*bundle, *lock, *key, *cache)
	case "source-tag":
		return hslsa.SourceTag(*bundle, *lock, *key, *cache)
	case "review":
		return hslsa.SourceReview(*bundle, *lock, *key)
	case "source-freeze":
		if *trust == "" && *policy == "" {
			return hslsa.SourceFreeze(*bundle, *lock, *key, *cache)
		}
		if err := need(trust, "trust-root", "source-freeze at Design L2"); err != nil {
			return err
		}
		if err := need(policy, "policy", "source-freeze at Design L2"); err != nil {
			return err
		}
		return hslsa.SourceFreezeL2(*bundle, *lock, *key, *cache, *trust, *policy)
	case "simulation":
		return hslsa.Simulation(*bundle, *lock, *key)
	case "synthesis":
		return hslsa.Synthesis(*bundle, *lock, *key)
	}
	if err := need(trust, "trust-root", "release"); err != nil {
		return err
	}
	if err := need(policy, "policy", "release"); err != nil {
		return err
	}
	return hslsa.DesignRelease(*bundle, *lock, *key, *trust, *policy)
}

func mfg(args []string) error {
	f := newFlags("mfg")
	bundle := f.str("bundle", "", true)
	scenario := f.str("scenario", "", true)
	keys := f.str("keys", "directory of <role>.key.pem", true)
	hold := f.str("withhold", "fields and files to withhold (JSON); disclosures go to the bundle's disclosures directory", false)
	if err := f.parse(args); err != nil {
		return err
	}
	w, err := hslsa.LoadWithholding(*hold)
	if err != nil {
		return err
	}
	return hslsa.Mfg(*bundle, *scenario, *keys, w)
}

func hbomCmd(args []string) error {
	f := newFlags("hbom")
	bundle := f.str("bundle", "", true)
	lock := f.str("lock", "", true)
	scenario := f.str("scenario", "", true)
	key := f.str("key", "", true)
	hold := f.str("withhold", "fields to withhold (JSON); disclosures go to the bundle's disclosures directory", false)
	if err := f.parse(args); err != nil {
		return err
	}
	w, err := hslsa.LoadWithholding(*hold)
	if err != nil {
		return err
	}
	return hslsa.BuildHBOM(*bundle, *lock, *scenario, *key, w)
}

func verify(args []string) error {
	f := newFlags("verify")
	bundle := f.str("bundle", "", true)
	trust := f.str("trust-root", "", true)
	policy := f.str("policy", "", true)
	units := f.str("units", "file with the serials of the units received", false)
	vsaKey := f.str("vsa-key", "", false)
	vsaOut := f.str("vsa-out", "", false)
	if err := f.parse(args); err != nil {
		return err
	}
	tr, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	_, _, err = hslsa.Verify(*bundle, tr, *policy, *units, *vsaKey, *vsaOut)
	return err
}

func escrow(args []string) error {
	act, rest, err := action(args, "audit", "check")
	if err != nil {
		return err
	}
	f := newFlags("escrow " + act)
	trust := f.str("trust-root", "audit: the sites' trust root; check: the buyer's, listing the auditor's key", true)
	policy := f.str("policy", "the buyer's policy", true)
	units := f.str("units", "file with the serials of the units the buyer received", true)
	bundle := f.str("bundle", "audit: the full bundle, with its disclosures", false)
	key := f.str("key", "audit: the auditor's signing key", false)
	vsaOut := f.str("vsa-out", "audit: directory for the VSAs the buyer receives", false)
	manifest := f.str("manifest", "audit: where the auditor keeps the escrow manifest", false)
	vsaDir := f.str("vsa-dir", "check: the VSAs the buyer received", false)
	if err := f.parse(rest); err != nil {
		return err
	}
	tr, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	if act == "check" {
		if err := need(vsaDir, "vsa-dir", "check"); err != nil {
			return err
		}
		return hslsa.EscrowCheck(*vsaDir, tr, *policy, *units)
	}
	for name, v := range map[string]*string{"bundle": bundle, "key": key, "vsa-out": vsaOut, "manifest": manifest} {
		if err := need(v, name, "audit"); err != nil {
			return err
		}
	}
	return hslsa.EscrowAudit(*bundle, tr, *policy, *units, *key, *vsaOut, *manifest)
}

func leaks(args []string) error {
	f := newFlags("leaks")
	bundle := f.str("bundle", "the producer's full bundle, with its disclosures", true)
	units := f.str("units", "the unit ids the viewer holds, such as a buyer's received units", true)
	vsaDir := f.str("vsa-dir", "the escrow VSAs the buyer receives", false)
	out := f.str("out", "directory for leaks.json and leaks.md", false)
	maxUnits := f.Int("max-units", hslsa.DefaultLeakLimits.MaxUnits, "largest lot to try when recovering a lot from its digest")
	maxMissing := f.Int("max-missing", hslsa.DefaultLeakLimits.MaxMissing, "most scrapped units to try per lot")
	if err := f.parse(args); err != nil {
		return err
	}
	known, err := hslsa.ReadUnits(*units)
	if err != nil {
		return err
	}
	rep, err := hslsa.Leaks(*bundle, known, *vsaDir, hslsa.LeakLimits{MaxUnits: *maxUnits, MaxMissing: *maxMissing})
	if err != nil {
		return err
	}
	md := hslsa.LeaksMarkdown(rep)
	if *out != "" {
		if err := hslsa.WriteJSON(filepath.Join(*out, "leaks.json"), rep); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*out, "leaks.md"), []byte(md), 0o644); err != nil {
			return err
		}
	}
	fmt.Print(md)
	return nil
}

func openlane(args []string) error {
	act, rest, err := action(args, "run", "release", "verify", "compare")
	if err != nil {
		return err
	}
	f := newFlags("openlane " + act)
	bundle := f.str("bundle", "", true)
	runDir := f.str("run-dir", "the OpenLane run directory the step records name files in", false)
	lock := f.str("lock", "", false)
	key := f.str("key", "", false)
	work := f.str("work", "run: empty directory to unpack the design and run OpenLane in", false)
	pdkRoot := f.str("pdk-root", "run: PDK root holding the enabled variant", false)
	trust := f.str("trust-root", "", false)
	otherBundle := f.str("other-bundle", "compare: the second run's bundle", false)
	otherRunDir := f.str("other-run-dir", "compare: the second run's run directory", false)
	report := f.str("report", "compare: directory for the JSON and Markdown report", false)
	rebuild := f.str("rebuild", "verify: a rebuild record to check as Design L4 evidence", false)
	rebuildTrust := f.str("rebuild-trust-root", "verify: the trust root naming the rebuilder's key", false)
	rebuildCheck := f.String("rebuild-check", "gds-bit-exact", "verify: the rebuild check the policy requires ("+strings.Join(hslsa.RebuildChecks, " or ")+")")
	if err := f.parse(rest); err != nil {
		return err
	}
	switch act {
	case "run":
		return hslsa.OpenLaneRun(*bundle, *lock, *key, *work, *pdkRoot)
	case "release":
		return hslsa.OpenLaneRelease(*bundle, *runDir, *key, *trust, *lock)
	case "verify":
		tr, err := hslsa.LoadTrustRoot(*trust)
		if err != nil {
			return err
		}
		records, final, err := hslsa.OpenLaneVerify(*bundle, *runDir, tr)
		if err != nil {
			return err
		}
		fmt.Printf("openlane tapeout check: PASSED, %d step records, %s sha256:%s\n",
			len(records), hslsa.S(final, "name"), hslsa.S(final, "digest", "sha256"))
		if *rebuild == "" {
			return nil
		}
		if *rebuildTrust == "" {
			return usageError{"--rebuild needs --rebuild-trust-root"}
		}
		rtr, err := hslsa.LoadTrustRoot(*rebuildTrust)
		if err != nil {
			return err
		}
		stmt, err := hslsa.CheckRebuild(*bundle, tr, records, final, *rebuild, rtr, *rebuildCheck)
		if err != nil {
			return err
		}
		fmt.Printf("design L4 rebuild check: PASSED, %s by %s\n",
			*rebuildCheck, hslsa.S(stmt, "predicate", "runDetails", "builder", "id"))
		return nil
	}
	trustA, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	trustB, err := hslsa.LoadTrustRoot(filepath.Join(*otherBundle, "trust-root.json"))
	if err != nil {
		return err
	}
	rep, err := hslsa.OpenLaneCompare(*bundle, *runDir, *otherBundle, *otherRunDir, trustA, trustB)
	if err != nil {
		return err
	}
	if err := hslsa.WriteJSON(filepath.Join(*report, "reproducibility.json"), rep); err != nil {
		return err
	}
	md := hslsa.ReproducibilityMarkdown(rep)
	if err := os.WriteFile(filepath.Join(*report, "reproducibility.md"), []byte(md), 0o644); err != nil {
		return err
	}
	if *key != "" {
		if err := hslsa.RebuildRecord(rep, *bundle, *otherBundle, *key, filepath.Join(*report, "rebuild.intoto.json")); err != nil {
			return err
		}
	}
	fmt.Print(md)
	return nil
}

func caliptra(args []string) error {
	act, rest, err := action(args, "ca", "firmware", "design", "fab", "rtl-model", "provision", "hbom", "review", "verify")
	if err != nil {
		return err
	}
	step := ""
	if act == "design" {
		if step, rest, err = action(rest, "source-freeze", "simulation", "rom-merge", "release"); err != nil {
			return err
		}
	}
	f := newFlags("caliptra " + act)
	switch act {
	case "ca":
		keys := f.str("keys", "", true)
		name := f.String("name", "HSLSA Example Caliptra IDevID CA", "")
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.IdentityCA(*keys, *name)
	case "firmware":
		bundle, lock := f.str("bundle", "", true), f.str("lock", "", true)
		build, key := f.str("build-dir", "", true), f.str("key", "", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.CaliptraFirmware(*bundle, *lock, *build, *key)
	case "design":
		bundle, lock, key := f.str("bundle", "", true), f.str("lock", "", true), f.str("key", "", true)
		trust, policy := f.str("trust-root", "", false), f.str("policy", "", false)
		if err := f.parse(rest); err != nil {
			return err
		}
		switch step {
		case "source-freeze":
			return hslsa.CaliptraSourceFreeze(*bundle, *lock, *key)
		case "simulation":
			return hslsa.CaliptraLint(*bundle, *lock, *key)
		case "rom-merge":
			return hslsa.CaliptraRomMerge(*bundle, *lock, *key)
		}
		if err := need(trust, "trust-root", "release"); err != nil {
			return err
		}
		if err := need(policy, "policy", "release"); err != nil {
			return err
		}
		return hslsa.CaliptraRelease(*bundle, *key, *trust, *policy)
	case "fab":
		bundle, devices := f.str("bundle", "", true), f.str("devices", "", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.CaliptraFab(*bundle, *devices)
	case "rtl-model":
		bundle, lock, out := f.str("bundle", "", true), f.str("lock", "", true), f.str("out", "", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.CaliptraRTLModel(*bundle, *lock, *out)
	case "provision":
		bundle, devices, keys := f.str("bundle", "", true), f.str("devices", "", true), f.str("keys", "", true)
		deviceBin, scenario, lock := f.str("device-bin", "", true), f.str("scenario", "", true), f.str("lock", "", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.CaliptraProvision(*bundle, *devices, *keys, *deviceBin, *scenario, *lock)
	case "hbom":
		bundle, lock := f.str("bundle", "", true), f.str("lock", "", true)
		scenario, key := f.str("scenario", "", true), f.str("key", "", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.CaliptraHBOM(*bundle, *lock, *scenario, *key)
	case "review":
		bundle, lock, key := f.str("bundle", "", true), f.str("lock", "", true), f.str("key", "simulated review provider key", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.CaliptraReview(*bundle, *lock, *key)
	}
	bundle, trust, policy := f.str("bundle", "", true), f.str("trust-root", "", true), f.str("policy", "", true)
	units, boots := f.str("units", "", true), f.str("boots", "", true)
	vsaKey, vsaOut := f.str("vsa-key", "", false), f.str("vsa-out", "", false)
	if err := f.parse(rest); err != nil {
		return err
	}
	tr, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	return hslsa.CaliptraVerify(*bundle, tr, *policy, *units, *boots, *vsaKey, *vsaOut)
}

func board(args []string) error {
	act, rest, err := action(args, "produce", "verify")
	if err != nil {
		return err
	}
	f := newFlags("board " + act)
	bundle := f.str("bundle", "", true)
	policy := f.str("policy", "", true)
	chip := f.str("chip-bundle", "produce: the chip vendor's bundle that ships with the chips", false)
	scenario := f.str("scenario", "produce: shipments and board build", false)
	designPath := f.str("design", "produce: the released board design", false)
	keys := f.str("keys", "produce: directory of <role>.key.pem", false)
	trust := f.str("trust-root", "verify: trust root for the board's signers", false)
	boards := f.str("boards", "verify: file with the serials of the boards received", false)
	vsaKey := f.str("vsa-key", "", false)
	vsaOut := f.str("vsa-out", "", false)
	if err := f.parse(rest); err != nil {
		return err
	}
	if act == "produce" {
		for name, v := range map[string]*string{"chip-bundle": chip, "scenario": scenario, "design": designPath, "keys": keys} {
			if err := need(v, name, "produce"); err != nil {
				return err
			}
		}
		return hslsa.BoardProduce(*bundle, *chip, *scenario, *designPath, *policy, *keys)
	}
	if err := need(trust, "trust-root", "verify"); err != nil {
		return err
	}
	tr, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	_, err = hslsa.BoardVerify(*bundle, tr, *policy, *boards, *vsaKey, *vsaOut)
	return err
}

func lotDigest(args []string) error {
	if len(args) != 1 {
		return usageError{"usage: hslsa lot-digest <unit list>"}
	}
	units, err := hslsa.ReadUnits(args[0])
	if err != nil {
		return err
	}
	d, err := hslsa.LotDigest(units)
	if err != nil {
		return err
	}
	fmt.Println(d)
	return nil
}

func subject(args []string) error {
	if len(args) != 1 {
		return usageError{"usage: hslsa subject <envelope>"}
	}
	stmt, err := hslsa.DecodeEnvelope(args[0])
	if err != nil {
		return err
	}
	subjects := hslsa.Objs(stmt, "subject")
	if len(subjects) == 0 {
		return fmt.Errorf("%s: no subject", args[0])
	}
	fmt.Println(hslsa.S(subjects[0], "name"), hslsa.S(subjects[0], "digest", "sha256"))
	return nil
}

func validateHBOM(args []string) error {
	if len(args) == 0 {
		return usageError{"usage: hslsa validate-hbom <statement or envelope>..."}
	}
	for _, path := range args {
		stmt, err := hslsa.ReadObj(path)
		if err != nil {
			return err
		}
		if _, ok := stmt["payload"]; ok {
			if stmt, err = hslsa.DecodeEnvelope(path); err != nil {
				return err
			}
		}
		if err := hslsa.ValidateHBOM(stmt["predicate"]); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Println(path, "valid")
	}
	return nil
}

func corimCmd(args []string) error {
	act, rest, err := action(args, "show", "appraise")
	if err != nil {
		return err
	}
	f := newFlags("corim " + act)
	file := f.str("corim", "signed CoRIM", true)
	trust := f.str("trust-root", "trust root holding the signer's key", act == "appraise")
	role := f.str("role", "trust root role allowed to sign the CoRIM", act == "appraise")
	if err := f.parse(rest); err != nil {
		return err
	}
	var c *hslsa.CoRIM
	if *trust != "" {
		if err := need(role, "role", "--trust-root"); err != nil {
			return err
		}
		t, err := hslsa.LoadTrustRoot(*trust)
		if err != nil {
			return err
		}
		if c, err = hslsa.OpenCoRIM(*file, t.Roles[*role], *file); err != nil {
			return err
		}
	} else {
		data, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		if c, err = hslsa.ParseCoRIM(data); err != nil {
			return err
		}
	}
	if act == "show" {
		verified := "signature not checked (pass --trust-root and --role)"
		if *trust != "" {
			verified = "signature verified with a " + *role + " key"
		}
		fmt.Printf("corim-id: %s\nprofile:  %s\nsigner:   %s, %s\n", c.ID, c.Profile, c.Signer, verified)
		for _, r := range c.RefValues {
			fmt.Printf("reference value: %s\n", r)
		}
		return nil
	}
	if f.NArg() == 0 {
		return usageError{"appraise needs at least one DER certificate"}
	}
	var certs []*x509.Certificate
	for _, path := range f.Args() {
		der, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, cert)
	}
	names := make([]string, len(certs))
	for i, p := range f.Args() {
		names[i] = filepath.Base(p)
	}
	lines, err := hslsa.AppraiseCerts(c.RefValues, certs, names)
	for _, l := range lines {
		fmt.Println(l)
	}
	if err != nil {
		return err
	}
	fmt.Printf("appraisal: PASSED against %s\n", c.ID)
	return nil
}

func safeCmd(args []string) error {
	act, rest, err := action(args, "sign", "show", "check")
	if err != nil {
		return err
	}
	f := newFlags("safe " + act)
	report := f.str("report", "sign: the JSON short-form report; show, check: the signed report", true)
	key := f.str("key", "sign: the review provider's private key", act == "sign")
	format := f.str("format", "sign: jws or corim", act == "sign")
	out := f.str("out", "sign: where to write the signed report", act == "sign")
	trust := f.str("trust-root", "trust root holding the review providers' keys", act == "check")
	policy := f.str("policy", "check: policy whose firmware.review the report must meet", act == "check")
	digest := f.str("digest", "check: the image digest as alg:hex; repeat with commas for more algorithms", act == "check")
	if err := f.parse(rest); err != nil {
		return err
	}
	if act == "sign" {
		rep, err := hslsa.ReadObj(*report)
		if err != nil {
			return err
		}
		signer, err := hslsa.LoadSigner(*key)
		if err != nil {
			return err
		}
		data, err := hslsa.SignSFR(rep, signer, *format)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, data, 0o644)
	}
	r, err := hslsa.ReadSFR(*report)
	if err != nil {
		return fmt.Errorf("%s: %w", *report, err)
	}
	if act == "show" {
		for _, l := range r.Describe() {
			fmt.Println(l)
		}
		if *trust == "" {
			fmt.Println("signature: not checked (pass --trust-root)")
			return nil
		}
		t, err := hslsa.LoadTrustRoot(*trust)
		if err != nil {
			return err
		}
		for _, role := range sortedRoles(t) {
			for _, k := range t.Roles[role] {
				if r.Verify(k.Public) == nil {
					fmt.Printf("signature: verified with a %s key\n", role)
					return nil
				}
			}
		}
		return fmt.Errorf("signature: verifies with no key in %s", *trust)
	}
	t, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	pol, err := hslsa.ReadObj(*policy)
	if err != nil {
		return err
	}
	image := hslsa.Obj{}
	for _, d := range strings.Split(*digest, ",") {
		alg, hex, found := strings.Cut(d, ":")
		if !found {
			return usageError{"--digest takes alg:hex, for example sha384:..."}
		}
		image[alg] = strings.ToLower(hex)
	}
	role, err := hslsa.AcceptSFR(r, hslsa.Obj{"digest": image}, t, hslsa.O(pol, "firmware", "review"))
	if err != nil {
		return err
	}
	fmt.Printf("review check: PASSED, signed by a %s key, %s\n", role, r.Provider)
	return nil
}

func sortedRoles(t *hslsa.TrustRoot) []string {
	roles := make([]string, 0, len(t.Roles))
	for r := range t.Roles {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	return roles
}
