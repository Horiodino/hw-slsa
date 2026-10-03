// Command hslsa is the reference tool for the Hardware Supply Chain Security
// Framework: hslsa <command> [flags]. Run hslsa help for the commands.
package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Horiodino/hw-slsa/tools/hslsa"
)

type command struct {
	help string
	run  func(args []string) error
}

var commands = map[string]command{
	"keygen":           {"generate ECDSA P-256 keys, one per role", keygen},
	"pubkey":           {"write the public key for a private key file or HSM key", pubkey},
	"keyid":            {"print the DSSE keyid for a public or private key", keyid},
	"hsm":              {"generate site keys in an HSM over PKCS#11", hsm},
	"trust-root":       {"build a trust root from <role>.pub.pem files", trustRoot},
	"design":           {"run and attest one design flow step", design},
	"adapt":            {"turn MES, STDF and SEMI E142 exports into a scenario for mfg and hbom", adapt},
	"import-shipments": {"turn shippers' packing lists, certificates of conformance and EPCIS events into a board scenario's shipments", importShipments},
	"mfg":              {"emit signed F1 to F4 records for the scenario lot", mfg},
	"fab-check":        {"the fab's check of the design release before mask making, signed as a VSA with its site key", fabCheck},
	"challenge":        {"challenge parts for their identity and print their unit names", challenge},
	"hbom":             {"build, validate and sign the HBOM", hbomCmd},
	"verify":           {"tapeout and lot receipt checks, then VSAs", verify},
	"escrow":           {"verifier escrow: the auditor's full check and VSAs, or the buyer's check of them", escrow},
	"leaks":            {"measure what the signed records and the escrow VSAs reveal", leaks},
	"openlane":         {"OpenLane 2 flow with a signed record per step", openlane},
	"eda":              {"sign a record per step from the Tcl hook in an EDA tool, or check them", eda},
	"caliptra":         {"the Caliptra example (e2e/caliptra)", caliptra},
	"board":            {"board-level example: shipments, A1 and board HBOM, or the buyer's board check", board},
	"fpga":             {"the FPGA board example with a board root of trust (e2e/fpga)", fpga},
	"provision":        {"provisioning station adapter: clear a job's images, then sign records from the station's export", provision},
	"lot-digest":       {"compute the lot digest of a unit list", lotDigest},
	"subject":          {"print the name and sha256 of an envelope's first subject", subject},
	"validate-hbom":    {"validate HBOM statements or envelopes against the schema", validateHBOM},
	"render":           {"render an HBOM as CycloneDX 1.6 or SPDX 3.1-RC1, or check a rendering", render},
	"corim":            {"show a signed CoRIM, or appraise DICE certificates against it", corimCmd},
	"safe":             {"sign, show or check an OCP S.A.F.E. short-form report", safeCmd},
	"pilot":            {"a buyer-run pilot: enroll or revoke site keys, build the trust root from them, measure a lot", pilot},
	"kit":              {"sign the pilot kit's provenance, or check a kit against it", kit},
	"sim":              {"simulated hardware: the virtual shuttle makes a lot's supplier exports by simulating the released netlist", sim},
	"pin":              {"print the toolPins entries for tools on this machine, for a policy to pin", pinCmd},
	"tlog":             {"the buyer's private transparency log for releases and manufacturing records: add records, sign checkpoints, prove and check", tlogCmd},
	"unit-check":       {"a buyer's check, without an auditor, that its units are in the lot final test committed to", unitCheck},
	"inspect":          {"an independent lab's L4 inspection: commit to a sampling seed before the lot is sealed, then inspect the sample it draws", inspectCmd},
	"release":          {"two-person review of a firmware release: an approver signs their approval of a release record", releaseCmd},
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
	if strings.HasPrefix(*key, "pkcs11:") {
		s, err := hslsa.LoadSigner(*key)
		if err != nil {
			return err
		}
		fmt.Println(s.Key.ID)
		return nil
	}
	text, err := os.ReadFile(*key)
	if err != nil {
		return err
	}
	var k hslsa.Key
	if t := strings.TrimSpace(string(text)); strings.Contains(t, "PRIVATE") || strings.HasPrefix(t, "pkcs11:") {
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

func hsm(args []string) error {
	act, rest, err := action(args, "keygen")
	if err != nil {
		return err
	}
	f := newFlags("hsm " + act)
	module := f.str("module", "PKCS#11 module (default $"+hslsa.PKCS11ModuleEnv+")", false)
	token := f.str("token", "label of the token to hold the keys", true)
	pinSource := f.str("pin-source", "file holding the user PIN (default $"+hslsa.PKCS11PINEnv+")", false)
	out := f.str("out", "directory for <role>.pkcs11 and <role>.pub.pem", true)
	if err := f.parse(rest); err != nil {
		return err
	}
	if f.NArg() == 0 {
		return usageError{"at least one role is required"}
	}
	if *module == "" {
		*module = os.Getenv(hslsa.PKCS11ModuleEnv)
	}
	if *module == "" {
		return usageError{"needs --module or $" + hslsa.PKCS11ModuleEnv}
	}
	pin := os.Getenv(hslsa.PKCS11PINEnv)
	if *pinSource != "" {
		data, err := os.ReadFile(*pinSource)
		if err != nil {
			return err
		}
		pin = strings.TrimRight(string(data), "\r\n")
	}
	for _, role := range f.Args() {
		s, err := hslsa.HSMKeygen(*module, *token, pin, *out, role)
		if err != nil {
			return err
		}
		fmt.Printf("%s %s\n", role, s.Key.ID)
	}
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
	step, rest, err := action(args, "ip-release", "source-tag", "review", "source-freeze", "simulation", "synthesis", "signoff", "release", "rerun-equivalence", "rebuild")
	if err != nil {
		return err
	}
	if step == "rebuild" {
		f := newFlags("design rebuild")
		bundle := f.str("bundle", "the design bundle whose release to rebuild", true)
		lock := f.str("lock", "the design's inputs lock", true)
		key := f.str("key", "the second builder's key (role rebuilder)", true)
		cache := f.str("cache", "where the second builder keeps the sources it fetches", false)
		out := f.str("out", "the rebuild record to write (default <bundle>/att/"+hslsa.DesignRebuildAtt+")", false)
		builderID := f.str("builder-id", "the second builder's id, which must not be the flow's", true)
		isolate := f.Bool("isolate", false, "run the tools in a sandbox, as a Design L3 flow does")
		if err := f.parse(rest); err != nil {
			return err
		}
		if *cache == "" {
			*cache = ".hslsa-cache"
		}
		if *out == "" {
			*out = filepath.Join(*bundle, "att", hslsa.DesignRebuildAtt)
		}
		os.Setenv("HSLSA_BUILDER_ID", *builderID)
		return hslsa.DesignRebuild(*bundle, *lock, *key, *cache, *out, *isolate)
	}
	if step == "rerun-equivalence" {
		f := newFlags("design rerun-equivalence")
		bundle := f.str("bundle", "the design bundle", true)
		trust := f.str("trust-root", "the buyer's trust root, which lists the flow platform's key", true)
		isolate := f.Bool("isolate", false, "run Yosys in a sandbox, as the flow did")
		if err := f.parse(rest); err != nil {
			return err
		}
		tr, err := hslsa.LoadTrustRoot(*trust)
		if err != nil {
			return err
		}
		return hslsa.RerunEquivalence(*bundle, tr, *isolate)
	}
	f := newFlags("design " + step)
	bundle := f.str("bundle", "", true)
	lock := f.str("lock", "", true)
	key := f.str("key", "", true)
	cache := f.str("cache", "", false)
	trust := f.str("trust-root", "", false)
	policy := f.str("policy", "", false)
	isolate := f.Bool("isolate", false, "run the step's tools in a sandbox of their own, with no network and no signing key in reach (Design L3)")
	reviewer := f.str("reviewer", "review: who approves, as \"Name <email>\" (default: the lock's freeze.reviewer); a second reviewer's approval goes beside the first", false)
	withholdPath := f.str("withhold", "source-freeze, simulation, synthesis, signoff, release: JSON file naming the fields to withhold, by step (see e2e/picorv32/withhold-design.json)", false)
	if err := f.parse(rest); err != nil {
		return err
	}
	if *cache == "" {
		*cache = ".hslsa-cache"
	}
	w, err := hslsa.LoadWithholding(*withholdPath)
	if err != nil {
		return err
	}
	switch step {
	case "ip-release":
		return hslsa.IPRelease(*bundle, *lock, *key, *cache)
	case "source-tag":
		return hslsa.SourceTag(*bundle, *lock, *key, *cache)
	case "review":
		return hslsa.SourceReview(*bundle, *lock, *key, *reviewer)
	case "source-freeze":
		if *trust == "" && *policy == "" {
			return hslsa.SourceFreeze(*bundle, *lock, *key, *cache, w)
		}
		if err := need(trust, "trust-root", "source-freeze at Design L2"); err != nil {
			return err
		}
		if err := need(policy, "policy", "source-freeze at Design L2"); err != nil {
			return err
		}
		return hslsa.SourceFreezeL2(*bundle, *lock, *key, *cache, *trust, *policy, w)
	case "simulation":
		return hslsa.Simulation(*bundle, *lock, *key, *isolate, w)
	case "synthesis":
		return hslsa.Synthesis(*bundle, *lock, *key, *isolate, w)
	case "signoff":
		return hslsa.Equivalence(*bundle, *lock, *key, *isolate, w)
	}
	if err := need(trust, "trust-root", "release"); err != nil {
		return err
	}
	if err := need(policy, "policy", "release"); err != nil {
		return err
	}
	return hslsa.DesignRelease(*bundle, *lock, *key, *trust, *policy, w)
}

func adapt(args []string) error {
	f := newFlags("adapt")
	config := f.str("config", "adapter configuration (JSON): each site and the exports it hands over", true)
	out := f.str("out", "the scenario to write", true)
	if err := f.parse(args); err != nil {
		return err
	}
	return hslsa.Adapt(*config, *out)
}

func importShipments(args []string) error {
	f := newFlags("import-shipments")
	config := f.str("config", "importer configuration (JSON): each shipment's id and the exports its shipper hands over", true)
	scenario := f.str("scenario", "the board scenario whose shipments the exports replace", true)
	out := f.str("out", "the scenario to write", true)
	if err := f.parse(args); err != nil {
		return err
	}
	return hslsa.ImportShipments(*config, *scenario, *out)
}

func sim(args []string) error {
	act, rest, err := action(args, "shuttle")
	if err != nil {
		return err
	}
	switch act {
	case "shuttle":
		f := newFlags("sim shuttle")
		bundle := f.str("bundle", "design bundle holding the release and the netlist it names", true)
		lock := f.str("lock", "the design's inputs lock (synthesis top and RTL files)", true)
		config := f.str("config", "shuttle configuration (JSON): sites, lot, wafer grid, defect rates and seed", true)
		out := f.str("out", "directory for the exports, adapter.json and report.json", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.Shuttle(hslsa.ShuttleOptions{Bundle: *bundle, Lock: *lock, Config: *config, Out: *out})
	}
	return nil
}

func mfg(args []string) error {
	f := newFlags("mfg")
	bundle := f.str("bundle", "", true)
	scenario := f.str("scenario", "", true)
	keys := f.str("keys", "directory of <role>.key.pem", true)
	hold := f.str("withhold", "fields and files to withhold (JSON); disclosures go to the bundle's disclosures directory", false)
	sign := f.str("sign", "comma-separated roles to sign for; records of other roles must already be in the bundle (default: every role)", false)
	devices := f.str("devices", "directory that holds the parts, when the scenario provisions unit identities", false)
	commitment := f.str("inspection-commitment", "L4: the inspection lab's commitment to its sampling seed, which final test consumes as it seals the lot", false)
	if err := f.parse(args); err != nil {
		return err
	}
	w, err := hslsa.LoadWithholding(*hold)
	if err != nil {
		return err
	}
	return hslsa.MfgInspected(*bundle, *scenario, *keys, w, splitList(*sign), *devices, *commitment)
}

func fabCheck(args []string) error {
	f := newFlags("fab-check")
	bundle := f.str("bundle", "", true)
	trust := f.str("trust-root", "the fab's trust root for the design records", true)
	policy := f.str("policy", "the fab's policy for the design records", true)
	key := f.str("key", "the fab's site key", true)
	if err := f.parse(args); err != nil {
		return err
	}
	tr, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	return hslsa.FabReleaseCheck(*bundle, tr, *policy, *key)
}

func challenge(args []string) error {
	f := newFlags("challenge")
	parts := f.str("parts", "directory with one directory per part", true)
	trust := f.str("trust-root", "trust root listing the identity CA", true)
	if err := f.parse(args); err != nil {
		return err
	}
	tr, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	units, err := hslsa.ChallengeParts(tr, *parts)
	if err != nil {
		return err
	}
	for _, u := range units {
		fmt.Println(u)
	}
	return nil
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
	units := f.str("units", "file with the serials of the units received, or a directory of the parts received, which must answer an identity challenge", false)
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

func eda(args []string) error {
	act, rest, err := action(args, "run", "verify")
	if err != nil {
		return err
	}
	f := newFlags("eda " + act)
	bundle := f.str("bundle", "bundle for the records; its artifacts/source.tar, if present, is the frozen source", true)
	root := f.str("root", "directory that subject and input names are relative to (run: default the working directory; verify: re-hash every subject under it)", false)
	pdk := f.str("pdk", "PDK tree that pdk inputs come from (run: pinned by tree digest; verify: re-hash the tree and each PDK file)", false)
	spool := f.str("spool", "run: new directory for the hook's events", false)
	key := f.str("key", "run: the flow-platform signing key", false)
	image := f.str("image", "run: the container image the tool runs in, pinned by digest", false)
	trust := f.str("trust-root", "verify: the trust root", false)
	hook := f.str("hook", "verify: require every record to name this hook file", false)
	require := f.str("require-steps", "verify: comma-separated design steps that must each have a record", false)
	if err := f.parse(rest); err != nil {
		return err
	}
	if act == "run" {
		if err := need(spool, "spool", "run"); err != nil {
			return err
		}
		if err := need(key, "key", "run"); err != nil {
			return err
		}
		if f.NArg() == 0 {
			return usageError{"eda run: give the tool command after --"}
		}
		return hslsa.EDARun(hslsa.EDAOptions{Bundle: *bundle, Spool: *spool, Key: *key, Root: *root, PDK: *pdk, Image: *image, Cmd: f.Args()})
	}
	if err := need(trust, "trust-root", "verify"); err != nil {
		return err
	}
	tr, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	var steps []string
	if *require != "" {
		steps = strings.Split(*require, ",")
	}
	records, err := hslsa.EDAVerify(hslsa.EDAVerifyOptions{Bundle: *bundle, Trust: tr, Root: *root, PDK: *pdk, RequireSteps: steps, Hook: *hook})
	if err != nil {
		return err
	}
	fmt.Printf("eda check: PASSED, %d step record(s)\n", len(records))
	for _, r := range records {
		hw := r["predicate"].(map[string]any)["hwFlow"]
		fmt.Printf("  %-14s %-24s %s\n", hslsa.S(hw, "step"), hslsa.S(hw, "toolStep"), hslsa.S(hslsa.Objs(hw, "tools")[0], "name"))
	}
	return nil
}

func caliptra(args []string) error {
	act, rest, err := action(args, "ca", "firmware", "firmware-rebuild", "design", "fab", "rtl-model", "provision", "hbom", "review", "verify")
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
	case "firmware-rebuild":
		bundle, lock := f.str("bundle", "", true), f.str("lock", "", true)
		build := f.str("build-dir", "the second builder's own build of the caliptra-sw commit the lock pins", true)
		key := f.str("key", "the second builder's key (role rebuilder)", true)
		builderID := f.str("builder-id", "the second builder's id, which must not be the release's", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		os.Setenv("HSLSA_BUILDER_ID", *builderID)
		return hslsa.CaliptraFirmwareRebuild(*bundle, *lock, *build, *key)
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
	chipParts := f.str("chip-parts", "produce, Assembly L3: directory of the chips shipped to the EMS, one per marked serial, which the EMS challenges before placement", false)
	boardsOut := f.str("boards-out", "produce, Assembly L3: directory to put the built boards in, one per serial", false)
	commitment := f.str("inspection-commitment", "produce, Assembly L4: the inspection lab's commitment to its sampling seed, which A1 consumes as it seals the board lot", false)
	trust := f.str("trust-root", "verify: trust root for the board's signers", false)
	boards := f.str("boards", "verify: file with the serials of the boards received, or a directory of the boards received, whose identity parts must answer a challenge", false)
	vsaKey := f.str("vsa-key", "", false)
	vsaOut := f.str("vsa-out", "", false)
	setPartRoots := partRootFlags(f)
	if err := f.parse(rest); err != nil {
		return err
	}
	if err := setPartRoots(); err != nil {
		return err
	}
	if act == "produce" {
		for name, v := range map[string]*string{"chip-bundle": chip, "scenario": scenario, "design": designPath, "keys": keys} {
			if err := need(v, name, "produce"); err != nil {
				return err
			}
		}
		if *chipParts != "" {
			if err := need(boardsOut, "boards-out", "the chips are challenged (--chip-parts)"); err != nil {
				return err
			}
			return hslsa.BoardProduceParts(*bundle, *chip, *scenario, *designPath, *policy, *keys,
				&hslsa.BoardParts{Chips: *chipParts, Boards: *boardsOut, Commitment: *commitment})
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

func fpga(args []string) error {
	act, rest, err := action(args, "rot-firmware", "rot-firmware-rebuild", "rot-job", "rot-station", "rot-hbom", "firmware", "firmware-rebuild", "design", "image",
		"produce", "provision", "boot", "update-build", "after-sale", "verify")
	if err != nil {
		return err
	}
	step := ""
	if act == "design" {
		if step, rest, err = action(rest, "simulation", "synthesis", "routing", "signoff", "bitstream"); err != nil {
			return err
		}
	}
	if act == "after-sale" {
		if step, rest, err = action(rest, hslsa.AfterSaleEvents...); err != nil {
			return err
		}
	}
	f := newFlags("fpga " + act)
	switch act {
	case "rot-firmware":
		bundle, src := f.str("bundle", "", true), f.str("src", "the root of trust firmware's Go package", true)
		key, cs := f.str("key", "", true), f.str("code-signer", "", true)
		svn := f.Int64("svn", 1, "security version")
		isolate := f.Bool("isolate", false, "build in a sandbox with no network and no signing key in reach (SLSA Build L3)")
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.RoTFirmware(*bundle, *src, *key, *cs, *svn, *isolate)
	case "rot-firmware-rebuild":
		bundle := f.str("bundle", "the root of trust bundle whose firmware release to rebuild", true)
		src := f.str("src", "the second builder's own copy of the root of trust firmware's Go package", true)
		key := f.str("key", "the second builder's key (role rebuilder)", true)
		out := f.str("out", "the rebuild record to write (default <bundle>/att/"+hslsa.FWRebuildAtt(hslsa.RoTFWAtt)+")", false)
		builderID := f.str("builder-id", "the second builder's id, which must not be the release's", true)
		isolate := f.Bool("isolate", false, "build in a sandbox with no network and no signing key in reach (SLSA Build L3)")
		if err := f.parse(rest); err != nil {
			return err
		}
		if *out == "" {
			*out = filepath.Join(*bundle, "att", hslsa.FWRebuildAtt(hslsa.RoTFWAtt))
		}
		os.Setenv("HSLSA_BUILDER_ID", *builderID)
		return hslsa.RoTFirmwareRebuild(*bundle, *src, *key, *out, *isolate)
	case "rot-job":
		bundle, scenario := f.str("bundle", "", true), f.str("scenario", "", true)
		export := f.str("export", "the station's export directory, where its job file goes", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.RoTJob(*bundle, *scenario, *export)
	case "rot-station":
		bundle, devices := f.str("bundle", "", true), f.str("devices", "directory for the root of trust units", true)
		keys, export := f.str("keys", "", true), f.str("export", "the station's export directory, with its job file", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.RoTStation(*bundle, *devices, *keys, *export)
	case "rot-hbom":
		bundle, lock := f.str("bundle", "", true), f.str("lock", "", true)
		scenario, key := f.str("scenario", "", true), f.str("key", "", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.RoTHBOM(*bundle, *lock, *scenario, *key)
	case "firmware":
		bundle, lock, key := f.str("bundle", "", true), f.str("lock", "", true), f.str("key", "", true)
		cache := f.str("cache", "", false)
		isolate := f.Bool("isolate", false, "build in a sandbox with no network and no signing key in reach (SLSA Build L3)")
		if err := f.parse(rest); err != nil {
			return err
		}
		if *cache == "" {
			*cache = ".hslsa-cache"
		}
		return hslsa.FPGAFirmware(*bundle, *lock, *key, *cache, *isolate)
	case "firmware-rebuild":
		bundle := f.str("bundle", "the FPGA design bundle whose firmware release to rebuild", true)
		lock := f.str("lock", "the inputs lock, which pins the firmware's sources", true)
		key := f.str("key", "the second builder's key (role rebuilder)", true)
		cache := f.str("cache", "where the second builder keeps the sources it fetches", false)
		out := f.str("out", "the rebuild record to write (default <bundle>/att/"+hslsa.FWRebuildAtt(hslsa.FPGAFWAtt)+")", false)
		builderID := f.str("builder-id", "the second builder's id, which must not be the release's", true)
		isolate := f.Bool("isolate", false, "build in a sandbox with no network and no signing key in reach (SLSA Build L3)")
		if err := f.parse(rest); err != nil {
			return err
		}
		if *cache == "" {
			*cache = ".hslsa-cache"
		}
		if *out == "" {
			*out = filepath.Join(*bundle, "att", hslsa.FWRebuildAtt(hslsa.FPGAFWAtt))
		}
		os.Setenv("HSLSA_BUILDER_ID", *builderID)
		return hslsa.FPGAFirmwareRebuild(*bundle, *lock, *key, *cache, *out, *isolate)
	case "design":
		bundle, lock, key := f.str("bundle", "", true), f.str("lock", "", true), f.str("key", "", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		run := map[string]func(string, string, string) error{
			"simulation": hslsa.FPGASimulation, "synthesis": hslsa.FPGASynthesis, "routing": hslsa.FPGARouting,
			"signoff": hslsa.FPGASignoff, "bitstream": hslsa.FPGABitstream,
		}
		return run[step](*bundle, *lock, *key)
	case "image":
		bundle, lock, scenario := f.str("bundle", "", true), f.str("lock", "", true), f.str("scenario", "the board scenario (product)", true)
		key, cs := f.str("key", "", true), f.str("code-signer", "", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.FPGAImage(*bundle, *lock, *scenario, *key, *cs)
	case "produce":
		bundle, rot, design := f.str("bundle", "", true), f.str("rot-bundle", "", true), f.str("design-bundle", "", true)
		scenario, designPath := f.str("scenario", "", true), f.str("design", "the released board design", true)
		policy, keys := f.str("policy", "", true), f.str("keys", "", true)
		chipParts := f.str("chip-parts", "Assembly L3: directory of the root of trust parts shipped to the EMS, one per marked serial, which the EMS challenges before placement", false)
		boardsOut := f.str("boards-out", "Assembly L3: directory to put the built boards in, one per serial", false)
		commitment := f.str("inspection-commitment", "Assembly L4: the inspection lab's commitment to its sampling seed, which A1 consumes as it seals the board lot", false)
		setPartRoots := partRootFlags(f)
		if err := f.parse(rest); err != nil {
			return err
		}
		if err := setPartRoots(); err != nil {
			return err
		}
		var phys *hslsa.BoardParts
		if *chipParts != "" {
			if err := need(boardsOut, "boards-out", "the parts are challenged (--chip-parts)"); err != nil {
				return err
			}
			phys = &hslsa.BoardParts{Chips: *chipParts, Boards: *boardsOut, Commitment: *commitment}
		}
		return hslsa.FPGABoardProduce(*bundle, *rot, *design, *scenario, *designPath, *policy, *keys, phys)
	case "provision":
		bundle, devices := f.str("bundle", "", true), f.str("devices", "the root of trust units as shipped", true)
		boards, scenario, keys := f.str("boards", "directory for the programmed boards", true), f.str("scenario", "", true), f.str("keys", "", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.FPGAProvision(*bundle, *devices, *boards, *scenario, *keys)
	case "boot":
		bundle, boards := f.str("bundle", "", true), f.str("boards", "directory of programmed boards", true)
		list, out := f.str("list", "file with the serials to boot", true), f.str("out", "", true)
		noSoC := f.Bool("no-soc", false, "skip the SoC simulation")
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.FPGABootAll(*bundle, *boards, *list, *out, !*noSoC)
	case "update-build":
		bundle := f.str("bundle", "the board bundle; the update goes in its updates/<id>", true)
		id := f.str("id", "the update's name", true)
		lock := f.str("lock", "the inputs lock for the update: the same design, the firmware to ship", true)
		scenario := f.str("scenario", "the board scenario (product)", true)
		key, cs := f.str("key", "the firmware platform's key", true), f.str("code-signer", "", true)
		cache := f.str("cache", "", false)
		isolate := f.Bool("isolate", false, "build the firmware in a sandbox with no network and no signing key in reach (SLSA Build L3)")
		if err := f.parse(rest); err != nil {
			return err
		}
		if *cache == "" {
			*cache = ".hslsa-cache"
		}
		dir, err := hslsa.FPGAUpdateBuild(*bundle, *id, *lock, *scenario, *key, *cs, *cache, *isolate)
		if err == nil {
			fmt.Printf("update %s built in %s\n", *id, dir)
		}
		return err
	case "after-sale":
		bundle, serial := f.str("bundle", "the board bundle", true), f.str("board", "the board's serial", true)
		key := f.str("key", "the signer's key: field-updater, returns-site, repair-site or board-owner, by event", true)
		site, country := f.str("site", "the signing site's name", true), f.str("country", "the signing site's country", false)
		boards := f.str("boards", "field-update: directory of the boards, one per serial", false)
		update := f.str("update", "field-update: the update's directory (<bundle>/updates/<id>)", false)
		from := f.str("from", "return: who sent the board back", false)
		reason := f.str("reason", "return: why it came back", false)
		disposition := f.str("disposition", "return: repair or scrap", false)
		order := f.str("order", "rework: the rework order (reason, and parts removed and placed by refDes)", false)
		to := f.str("to", "reship: who the board ships to", false)
		shipment := f.str("shipment", "reship: the shipment's id", false)
		scenario := f.str("scenario", "a scenario whose afterSale.simulated marks the record as made by a simulation", false)
		if err := f.parse(rest); err != nil {
			return err
		}
		sim, err := hslsa.AfterSaleSimulated(*scenario)
		if err != nil {
			return err
		}
		s := hslsa.Obj{"name": *site}
		if *country != "" {
			s["country"] = *country
		}
		switch step {
		case "field-update":
			if err := need(boards, "boards", "after-sale field-update"); err != nil {
				return err
			}
			if err := need(update, "update", "after-sale field-update"); err != nil {
				return err
			}
			return hslsa.FPGAFieldUpdate(*bundle, *boards, *serial, *update, *key, s, sim)
		case "return":
			if err := need(from, "from", "after-sale return"); err != nil {
				return err
			}
			return hslsa.FPGAReturn(*bundle, *serial, *key, s, sim, *from, *reason, *disposition)
		case "rework":
			if err := need(order, "order", "after-sale rework"); err != nil {
				return err
			}
			return hslsa.FPGARework(*bundle, *serial, *key, s, sim, *order)
		default:
			if err := need(to, "to", "after-sale reship"); err != nil {
				return err
			}
			return hslsa.FPGAReship(*bundle, *serial, *key, s, sim, *to, *shipment)
		}
	}
	bundle, trust, policy := f.str("bundle", "", true), f.str("trust-root", "", true), f.str("policy", "", true)
	boards, boots := f.str("boards", "file with the serials of the boards received", false), f.str("boots", "what each received board returned at boot", false)
	vsaKey, vsaOut := f.str("vsa-key", "", false), f.str("vsa-out", "", false)
	setPartRoots := partRootFlags(f)
	if err := f.parse(rest); err != nil {
		return err
	}
	if err := setPartRoots(); err != nil {
		return err
	}
	tr, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	return hslsa.FPGAVerify(*bundle, tr, *policy, *boards, *boots, *vsaKey, *vsaOut)
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

// readStatement reads an in-toto statement, or the statement in an envelope
// without checking its signature.
func readStatement(path string) (map[string]any, error) {
	stmt, err := hslsa.ReadObj(path)
	if err != nil {
		return nil, err
	}
	if _, ok := stmt["payload"]; ok {
		return hslsa.DecodeEnvelope(path)
	}
	return stmt, nil
}

func validateHBOM(args []string) error {
	if len(args) == 0 {
		return usageError{"usage: hslsa validate-hbom <statement or envelope>..."}
	}
	for _, path := range args {
		stmt, err := readStatement(path)
		if err != nil {
			return err
		}
		if err := hslsa.ValidateHBOM(stmt["predicate"]); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Println(path, "valid")
	}
	return nil
}

func render(args []string) error {
	f := newFlags("render")
	in := f.str("hbom", "HBOM statement or envelope; an envelope's signature is not checked, so verify the HBOM first", true)
	format := f.str("format", "cyclonedx or spdx (to render)", false)
	out := f.str("out", "file to write (default: standard output)", false)
	created := f.str("created", "creation time YYYY-MM-DDTHH:MM:SSZ (default: SOURCE_DATE_EPOCH if set, else now)", false)
	check := f.str("check", "instead of rendering, check that this file is exactly what the HBOM renders to", false)
	if err := f.parse(args); err != nil {
		return err
	}
	stmt, err := readStatement(*in)
	if err != nil {
		return err
	}
	if *check != "" {
		got, err := hslsa.CheckRendering(stmt, *check, "rendering")
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s rendering of %s\n", *check, got, *in)
		return nil
	}
	if err := need(format, "format", "rendering"); err != nil {
		return err
	}
	formats := map[string]string{"cyclonedx": hslsa.FormatCycloneDX, "spdx": hslsa.FormatSPDX}
	name, ok := formats[strings.ToLower(*format)]
	if !ok {
		return usageError{fmt.Sprintf("invalid --format %q (choose from cyclonedx, spdx)", *format)}
	}
	when := *created
	if when == "" {
		when = hslsa.Now()
		if sde := os.Getenv("SOURCE_DATE_EPOCH"); sde != "" {
			n, err := strconv.ParseInt(sde, 10, 64)
			if err != nil {
				return usageError{"SOURCE_DATE_EPOCH is not an integer"}
			}
			when = time.Unix(n, 0).UTC().Format("2006-01-02T15:04:05Z")
		}
	}
	data, err := hslsa.RenderHBOM(stmt, name, when)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(*out, data, 0o644)
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
	act, rest, err := action(args, "sign", "show", "check", "simulate")
	if err != nil {
		return err
	}
	f := newFlags("safe " + act)
	if act == "simulate" {
		bundle := f.str("bundle", "", true)
		record := f.str("record", "the firmware record naming the image, relative to the bundle (att/...)", true)
		image := f.str("image", "the image's subject name in the record", true)
		vendor, product := f.str("vendor", "the device vendor the report names", true), f.str("product", "the product the report names", true)
		version := f.str("version", "the firmware version the report names", true)
		key := f.str("key", "the review provider's private key", true)
		format := f.str("format", "jws or corim", false)
		if err := f.parse(rest); err != nil {
			return err
		}
		if *format == "" {
			*format = hslsa.SFRFormatJWS
		}
		return hslsa.SimulateReview(*bundle, *record, *image, *vendor, *product, *version, *key, *format)
	}
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

func pinCmd(args []string) error {
	f := newFlags("pin")
	versionArg := f.str("version-arg", "the argument that makes the tools print their version (default --version)", false)
	if err := f.parse(args); err != nil {
		return err
	}
	if f.NArg() == 0 {
		return usageError{"usage: hslsa pin [--version-arg ARG] <tool>..."}
	}
	if *versionArg == "" {
		*versionArg = "--version"
	}
	var pins []hslsa.Obj
	for _, name := range f.Args() {
		pin, err := hslsa.ToolPin(name, *versionArg)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		pins = append(pins, pin)
	}
	data, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func inspectCmd(args []string) error {
	act, rest, err := action(args, "commit", "lot", "boards")
	if err != nil {
		return err
	}
	f := newFlags("inspect " + act)
	plan := f.str("plan", "the lab's inspection plan (JSON): lab, tracks, sample size, technique, regions and layers", true)
	key := f.str("key", "the lab's key (role inspection-lab)", true)
	switch act {
	case "commit":
		lot := f.str("lot", "the lot to inspect, as its URN or lot id", true)
		seedOut := f.str("seed-out", "where the lab keeps its seed until it inspects", true)
		out := f.str("out", "the signed commitment, which the party that seals the lot consumes", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.InspectionCommit(*plan, *lot, *key, *seedOut, *out)
	case "lot":
		bundle := f.str("bundle", "the chip bundle of the shipped lot", true)
		parts := f.str("parts", "the shipped parts, one directory per marked serial; the lab destroys the ones it samples", true)
		seed := f.str("seed", "the seed the lab committed to", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.InspectLot(*bundle, *parts, *plan, *seed, *key)
	}
	bundle := f.str("bundle", "the board bundle", true)
	boards := f.str("boards", "the built boards, one directory per serial", true)
	seed := f.str("seed", "the seed the lab committed to", true)
	if err := f.parse(rest); err != nil {
		return err
	}
	return hslsa.InspectBoards(*bundle, *boards, *plan, *seed, *key)
}

func tlogCmd(args []string) error {
	act, rest, err := action(args, "init", "add", "checkpoint", "consistency", "check", "verify-consistency")
	if err != nil {
		return err
	}
	f := newFlags("tlog " + act)
	logDir := f.str("log", "the log's directory", act != "check" && act != "verify-consistency")
	origin := f.str("origin", "init: the log's name; check: the log the record must be in", act == "init" || act == "check")
	key := f.str("key", "add, checkpoint: the log's private key", act == "add" || act == "checkpoint")
	record := f.str("record", "add, check: the signed record (its proof is written beside it)", act == "add" || act == "check")
	out := f.str("out", "checkpoint, consistency: where to write it", act == "checkpoint" || act == "consistency")
	from := f.str("from", "consistency: the older tree size", act == "consistency")
	trust := f.str("trust-root", "check, verify-consistency: trust root holding the log's key", act == "check" || act == "verify-consistency")
	role := f.str("role", "check, verify-consistency: the log's role (default "+hslsa.TLogRole+")", false)
	older := f.str("older", "verify-consistency: the checkpoint seen before", act == "verify-consistency")
	newer := f.str("newer", "verify-consistency: the checkpoint seen now", act == "verify-consistency")
	proof := f.str("proof", "verify-consistency: the consistency proof between them", false)
	if err := f.parse(rest); err != nil {
		return err
	}
	if *role == "" {
		*role = hslsa.TLogRole
	}
	switch act {
	case "init":
		return hslsa.TLogInit(*logDir, *origin)
	case "add":
		return hslsa.TLogAdd(*logDir, *key, *record)
	case "checkpoint":
		return hslsa.TLogCheckpoint(*logDir, *key, *out)
	case "consistency":
		n, err := strconv.Atoi(*from)
		if err != nil {
			return usageError{"--from takes a tree size"}
		}
		return hslsa.TLogConsistency(*logDir, n, *out)
	}
	t, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	if act == "verify-consistency" {
		if err := hslsa.TLogVerifyConsistency(t, *role, *older, *newer, *proof); err != nil {
			return err
		}
		fmt.Println("consistency check: PASSED, the newer checkpoint extends the older")
		return nil
	}
	cp, err := hslsa.CheckLogged(t, *record, *role, *origin, filepath.Base(*record))
	if err != nil {
		return err
	}
	fmt.Printf("log check: PASSED, in %q at tree size %d\n", cp.Origin, cp.Size)
	return nil
}

func unitCheck(args []string) error {
	f := newFlags("unit-check")
	record := f.str("record", "final test's signed record (att/mfg-f4-final-test.intoto.json)", true)
	trust := f.str("trust-root", "trust root holding the test site's key", true)
	if err := f.parse(args); err != nil {
		return err
	}
	if f.NArg() == 0 {
		return usageError{"name the inclusion proofs of the units to check (artifacts/unit-proofs/<unit>.json)"}
	}
	t, err := hslsa.LoadTrustRoot(*trust)
	if err != nil {
		return err
	}
	return hslsa.UnitCheck(t, *record, f.Args())
}

func sortedRoles(t *hslsa.TrustRoot) []string {
	roles := make([]string, 0, len(t.Roles))
	for r := range t.Roles {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	return roles
}

func provision(args []string) error {
	act, rest, err := action(args, "gate", "adapt")
	if err != nil {
		return err
	}
	f := newFlags("provision " + act)
	bundle := f.str("bundle", "the bundle with the release, the image provenance and the trust root", true)
	profile := f.str("profile", "the station model's profile: how to read its export", true)
	station := f.str("station", "the site's station file: id, site, images, fuses, identity", true)
	export := f.str("export", "the station's export directory", true)
	var key *string
	if act == "adapt" {
		key = f.str("key", "the site key that signs the records", true)
	}
	if err := f.parse(rest); err != nil {
		return err
	}
	if act == "gate" {
		return hslsa.ProvisionGate(*bundle, *profile, *station, *export)
	}
	return hslsa.ProvisionAdapt(*bundle, *profile, *station, *export, *key)
}

// splitList splits a comma-separated flag value, dropping empty items.
func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseFlagTime(v, name string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t, nil
	}
	return time.Time{}, usageError{fmt.Sprintf("--%s: %q is not a date (2026-12-31) or an RFC 3339 time", name, v)}
}

// partRootFlags adds --part-trust-root and --part-policy, each repeatable as
// <part>=<file>, and returns a function that stores them in hslsa.PartRoots.
func partRootFlags(f *flags) func() error {
	var trusts, policies multiFlag
	f.Var(&trusts, "part-trust-root", "verify: <part>=<file>, your trust root for a part under parts/ (repeatable)")
	f.Var(&policies, "part-policy", "verify: <part>=<file>, your policy for a part under parts/ (repeatable)")
	return func() error {
		for _, set := range []struct {
			vals multiFlag
			flag string
			put  func(*hslsa.PartRoot, string)
		}{
			{trusts, "--part-trust-root", func(r *hslsa.PartRoot, v string) { r.TrustRoot = v }},
			{policies, "--part-policy", func(r *hslsa.PartRoot, v string) { r.Policy = v }},
		} {
			for _, v := range set.vals {
				part, file, ok := strings.Cut(v, "=")
				if !ok || part == "" || file == "" || strings.ContainsAny(part, `/\`) {
					return usageError{fmt.Sprintf("%s %q: want <part>=<file>, the part's directory under parts/", set.flag, v)}
				}
				r := hslsa.PartRoots[part]
				set.put(&r, file)
				hslsa.PartRoots[part] = r
			}
		}
		return nil
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// kitFiles reads name=path arguments; a bare path is named as written, so
// bin/hslsa-linux-amd64 run from the unpacked kit is the provenance's name.
func kitFiles(args []string) ([]hslsa.KitFile, error) {
	if len(args) == 0 {
		return nil, usageError{"at least one file is required"}
	}
	var files []hslsa.KitFile
	for _, a := range args {
		name, path, ok := strings.Cut(a, "=")
		if !ok {
			name, path = filepath.ToSlash(filepath.Clean(a)), a
		}
		if name == "" || path == "" {
			return nil, usageError{fmt.Sprintf("%q: want name=path or a path", a)}
		}
		files = append(files, hslsa.KitFile{Name: name, Path: path})
	}
	return files, nil
}

func kit(args []string) error {
	act, rest, err := action(args, "sign", "verify")
	if err != nil {
		return err
	}
	f := newFlags("kit " + act)
	switch act {
	case "sign":
		key := f.str("key", "the kit owner's private key file or PKCS#11 URI", true)
		commit := f.str("commit", "the full git commit the kit was built from", true)
		prov := f.str("provenance", "provenance envelope to write", true)
		sig := f.str("sig", "detached signature over the first file to write, for openssl", false)
		if err := f.parse(rest); err != nil {
			return err
		}
		files, err := kitFiles(f.Args())
		if err != nil {
			return err
		}
		s, err := hslsa.LoadSigner(*key)
		if err != nil {
			return err
		}
		return hslsa.SignKit(s, *commit, files, *prov, *sig)
	default:
		pub := f.str("pub", "the kit owner's public key, checked over a second channel", true)
		prov := f.str("provenance", "the kit's provenance envelope", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		files, err := kitFiles(f.Args())
		if err != nil {
			return err
		}
		commit, err := hslsa.VerifyKit(*pub, *prov, files)
		if err != nil {
			return err
		}
		fmt.Printf("kit OK: all %d named files match the provenance; built from commit %s\n", len(files), commit)
		return nil
	}
}

func pilot(args []string) error {
	act, rest, err := action(args, "enroll", "revoke", "trust-root", "measure")
	if err != nil {
		return err
	}
	f := newFlags("pilot " + act)
	switch act {
	case "enroll":
		buyerKey := f.str("buyer-key", "the buyer's root key", true)
		pub := f.str("pub", "the site's public key, as the site handed it over", true)
		out := f.str("out", "enrollment record to write", true)
		role := f.str("role", "the role the key signs for, such as osat-site", true)
		orgName := f.str("org-name", "the company that holds the key", true)
		orgID := f.str("org-id", "its identifier: lei:, duns:, cage:, uei: or gln:", true)
		site := f.str("site", "the site name its records give", true)
		country := f.str("country", "the site's country (ISO 3166 alpha-2)", false)
		custody := f.str("custody", "how the key is held: hsm or file", true)
		notBefore := f.str("not-before", "start of the enrollment (default now)", false)
		notAfter := f.str("not-after", "end of the enrollment", true)
		note := f.str("note", "how the buyer checked the key with the site", false)
		accScheme := f.str("accreditation", "the site's accreditation scheme, such as \"DMEA Trusted Supplier\" (L3 needs one the buyer's policy accepts)", false)
		accID := f.str("accreditation-id", "the accreditation's certificate or listing id", false)
		if err := f.parse(rest); err != nil {
			return err
		}
		nb := time.Now().UTC()
		if *notBefore != "" {
			if nb, err = parseFlagTime(*notBefore, "not-before"); err != nil {
				return err
			}
		}
		na, err := parseFlagTime(*notAfter, "not-after")
		if err != nil {
			return err
		}
		return hslsa.Enroll(*buyerKey, *pub, hslsa.Enrollment{Role: *role, OrgName: *orgName, OrgID: *orgID, Site: *site,
			Country: *country, Custody: *custody, NotBefore: nb, NotAfter: na, Note: *note,
			Accreditation: hslsa.Accreditation{Scheme: *accScheme, ID: *accID}}, *out)
	case "revoke":
		buyerKey := f.str("buyer-key", "the buyer's root key", true)
		pub := f.str("pub", "the public key to revoke", true)
		reason := f.str("reason", "why", true)
		out := f.str("out", "revocation record to write", true)
		if err := f.parse(rest); err != nil {
			return err
		}
		return hslsa.Revoke(*buyerKey, *pub, *reason, *out)
	case "trust-root":
		buyerPub := f.str("buyer-pub", "the buyer's root public key", true)
		dir := f.str("enrollments", "directory of enrollment and revocation records", true)
		out := f.str("out", "trust root to write", true)
		at := f.str("at", "time the trust root is for (default now)", false)
		if err := f.parse(rest); err != nil {
			return err
		}
		t := time.Now().UTC()
		if *at != "" {
			if t, err = parseFlagTime(*at, "at"); err != nil {
				return err
			}
		}
		_, err := hslsa.BuildPilotTrustRoot(*buyerPub, *dir, t, *out)
		return err
	}
	bundle := f.str("bundle", "the lot's bundle", true)
	trust := f.str("trust-root", "the buyer-run trust root", true)
	policy := f.str("policy", "the buyer's policy", true)
	units := f.str("units", "file with the serials of the units received", false)
	costs := f.str("costs", "what each party reports the lot cost it (JSON)", false)
	out := f.str("out", "directory for the lot's report and the pilot summary", true)
	if err := f.parse(rest); err != nil {
		return err
	}
	rep, err := hslsa.PilotMeasure(*bundle, *trust, *policy, *units, *costs)
	if err != nil {
		return err
	}
	name := strings.NewReplacer(":", "-", "/", "-").Replace(hslsa.S(rep, "lot"))
	if err := hslsa.WriteJSON(filepath.Join(*out, name+".json"), rep); err != nil {
		return err
	}
	md := hslsa.PilotMeasurementMarkdown(rep)
	if err := os.WriteFile(filepath.Join(*out, name+".md"), []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Print(md)
	if _, err := hslsa.PilotSummary(*out); err != nil {
		return err
	}
	if hslsa.S(rep, "check", "result") != "pass" {
		return fmt.Errorf("the lot failed its receipt check; the report says why")
	}
	return nil
}

func releaseCmd(args []string) error {
	_, rest, err := action(args, "approve")
	if err != nil {
		return err
	}
	f := newFlags("release approve")
	bundle := f.str("bundle", "the bundle holding the release record", true)
	record := f.str("record", "the release record, inside the bundle (for example att/fw-rot.intoto.json)", true)
	approver := f.str("approver", "the approver's name", true)
	key := f.str("key", "the approver's own key (role release-approver)", true)
	out := f.str("out", "the approval to write (default beside the record)", false)
	if err := f.parse(rest); err != nil {
		return err
	}
	return hslsa.ReleaseApprove(*bundle, *record, *approver, *key, *out)
}
