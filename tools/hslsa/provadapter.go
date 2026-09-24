package hslsa

// Provisioning station adapter (roadmap phase 3).
//
// A programming station at a fab, OSAT or EMS knows nothing about HSLSA. It
// runs a job file and writes its own export: the job, a log with one row per
// operation on each unit, a readback dump of every image it wrote, and the
// identity files it exchanged with the identity CA. The adapter turns that
// export, unchanged, into one signed fw-provisioning record per unit:
//
//	gate   before the job runs: check every image the job file loads against
//	       its provenance, and write down that the job was cleared, and when
//	adapt  after the job: read the export through the station's profile,
//	       check each unit's last session, and sign one record per unit
//
// Two files configure it. A profile describes one station model's export: the
// job file's layout, the log's file, delimiter, columns and time format, and
// the words the station uses for each operation. A station file describes one
// station at one site programming one part: its id, site and stage, each
// image's role, storage and provenance, the type of each fuse field, which
// fields are secrets, the lifecycle fuses and the identity scheme. A second
// station model needs only a new profile.
//
// The adapter signs with the site's key through stationSigner, the one place
// that knows where the key lives.

import (
	"bytes"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// stationSigner opens the key a site signs its provisioning records with:
// a PEM file, or a key in the site's HSM by PKCS#11 URI or <role>.pkcs11
// file, as LoadSigner takes them. It is the one place to change if a
// station needs more; nothing else in the adapter depends on where the key
// lives.
var stationSigner = func(ref string) (*Signer, error) { return LoadSigner(ref) }

// ProvisioningDir holds what the adapter keeps in the bundle: the job file,
// the gate and each unit's log rows.
const ProvisioningDir = "provisioning"

// Profile and station files

var profileKeys = []string{
	"model", "job.file", "job.id", "job.lot", "job.imageSection", "job.imageFile", "job.imageRegion", "job.imageSha256",
	"log.file", "log.timeLayout", "log.pass",
	"log.columns.time", "log.columns.unit", "log.columns.op", "log.columns.target", "log.columns.value", "log.columns.result",
	"ops.begin", "ops.end", "ops.program", "ops.verify", "ops.fuseWrite", "ops.fuseRead",
}

// ReadStationProfile reads a station model's profile and checks it names every field the adapter reads.
func ReadStationProfile(path string) (Obj, error) {
	p, err := ReadObj(path)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, k := range profileKeys {
		if S(p, strings.Split(k, ".")...) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s: profile does not set %s", path, strings.Join(missing, ", "))
	}
	if d := S(p, "log", "delimiter"); len([]rune(d)) > 1 {
		return nil, fmt.Errorf("%s: log.delimiter must be one character", path)
	}
	return p, nil
}

// ReadStationFile reads the site's description of one station.
func ReadStationFile(path string) (Obj, error) {
	s, err := ReadObj(path)
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"station", "stage", "lotId"} {
		if S(s, k) == "" {
			return nil, fmt.Errorf("%s: station file does not set %s", path, k)
		}
	}
	if S(s, "site", "name") == "" {
		return nil, fmt.Errorf("%s: station file does not set site.name", path)
	}
	if len(O(s, "images")) == 0 {
		return nil, fmt.Errorf("%s: station file lists no images", path)
	}
	for name, img := range O(s, "images") {
		if S(img, "provenance") == "" || S(img, "signer") == "" {
			return nil, fmt.Errorf("%s: image %s needs provenance and signer", path, name)
		}
	}
	return s, nil
}

// Job files

// iniFile is a job file as sections of key = value pairs, in file order.
type iniFile struct {
	sections []string
	values   map[string]map[string]string
}

func (f *iniFile) get(dotted string) string {
	i := strings.LastIndex(dotted, ".")
	if i < 0 {
		return ""
	}
	return f.values[dotted[:i]][dotted[i+1:]]
}

// parseINI reads [section] headers and key = value lines; ; and # start comments.
func parseINI(data []byte) (*iniFile, error) {
	f := &iniFile{values: map[string]map[string]string{}}
	section := ""
	for n, line := range splitLines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: unclosed section header", n+1)
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if _, dup := f.values[section]; dup {
				return nil, fmt.Errorf("line %d: section [%s] appears twice", n+1, section)
			}
			f.sections = append(f.sections, section)
			f.values[section] = map[string]string{}
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found || section == "" {
			return nil, fmt.Errorf("line %d: expected key = value inside a section", n+1)
		}
		f.values[section][strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return f, nil
}

// jobImage is one image a job file loads.
type jobImage struct {
	Name, File, Region, SHA256 string
}

// stationJob is what the adapter reads from a job file.
type stationJob struct {
	ID, Lot string
	Images  []jobImage
	Path    string
}

var (
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexDigits = regexp.MustCompile(`^[0-9a-f]*$`)
)

// readJob reads the job file in an export through the profile.
func readJob(export string, profile Obj) (*stationJob, error) {
	path := filepath.Join(export, S(profile, "job", "file"))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ini, err := parseINI(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	job := &stationJob{ID: ini.get(S(profile, "job", "id")), Lot: ini.get(S(profile, "job", "lot")), Path: path}
	if job.ID == "" {
		return nil, fmt.Errorf("%s: no job id at %s", path, S(profile, "job", "id"))
	}
	prefix := S(profile, "job", "imageSection")
	regions := map[string]bool{}
	for _, sec := range ini.sections {
		if sec != prefix && !strings.HasPrefix(sec, prefix+".") && !strings.HasPrefix(sec, prefix+" ") {
			continue
		}
		v := ini.values[sec]
		img := jobImage{
			File:   v[S(profile, "job", "imageFile")],
			Region: v[S(profile, "job", "imageRegion")],
			SHA256: strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(v[S(profile, "job", "imageSha256")], "SHA256:"), "sha256:")),
		}
		img.Name = filepath.Base(filepath.FromSlash(img.File))
		if img.File == "" || img.Region == "" || !hex64.MatchString(img.SHA256) {
			return nil, fmt.Errorf("%s: [%s] needs a file, a region and a sha256", path, sec)
		}
		if regions[img.Region] {
			return nil, fmt.Errorf("%s: region %s is loaded twice", path, img.Region)
		}
		regions[img.Region] = true
		job.Images = append(job.Images, img)
	}
	if len(job.Images) == 0 {
		return nil, fmt.Errorf("%s: the job loads no images", path)
	}
	return job, nil
}

// insideExport resolves a path the station wrote, refusing one that leaves the export.
func insideExport(export, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", fmt.Errorf("export path %q is not relative", rel)
	}
	p := filepath.Join(export, filepath.FromSlash(rel))
	if r, err := filepath.Rel(export, p); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("export path %q leaves the export", rel)
	}
	return p, nil
}

// isOp says whether a log row is one of the named operations; an operation
// the profile leaves empty matches no row.
func isOp(profile Obj, r logRow, names ...string) bool {
	for _, n := range names {
		if op := S(profile, "ops", n); op != "" && r.Op == op {
			return true
		}
	}
	return false
}

var unsafeName = regexp.MustCompile(`[^a-z0-9._-]+`)

// fileSlug makes a station's job id safe to use in a file name.
func fileSlug(id string) string { return unsafeName.ReplaceAllString(strings.ToLower(id), "-") }

func gateName(jobID string) string { return "gate-" + fileSlug(jobID) + ".json" }

// The gate

// ProvisionGate checks every image the job loads before the station runs it:
// the file the job loads has the digest the job names, and that digest is a
// subject of the image's provenance, signed by the role the station file
// names. It writes the cleared job to the bundle; it writes nothing, and the
// job must not run, if any image fails.
func ProvisionGate(bundle, profilePath, stationPath, export string) error {
	profile, err := ReadStationProfile(profilePath)
	if err != nil {
		return err
	}
	station, err := ReadStationFile(stationPath)
	if err != nil {
		return err
	}
	job, err := readJob(export, profile)
	if err != nil {
		return err
	}
	trust, err := LoadTrustRoot(filepath.Join(bundle, "trust-root.json"))
	if err != nil {
		return err
	}
	var cleared []Obj
	for _, img := range job.Images {
		conf := O(station, "images", img.Name)
		if conf == nil {
			return fmt.Errorf("gate: job %s loads %s, which the station file does not list", job.ID, img.Name)
		}
		path, err := insideExport(export, img.File)
		if err != nil {
			return fmt.Errorf("gate: %v", err)
		}
		d, err := sha256File(path)
		if err != nil {
			return fmt.Errorf("gate: job %s loads %s: %v", job.ID, img.File, err)
		}
		if d != img.SHA256 {
			return failf("gate: %s is not the image the job file names (sha256 %s, job says %s)", img.File, d[:16], img.SHA256[:16])
		}
		prov, err := trust.Open(filepath.Join(bundle, "att", S(conf, "provenance")), S(conf, "signer"), SLSAProvenance)
		if err != nil {
			return failf("gate: %s: %v", img.Name, err)
		}
		if !sha256Set(Objs(prov, "subject"))[d] {
			return failf("gate: %s has no provenance: %s does not name sha256 %s", img.Name, S(conf, "provenance"), d[:16])
		}
		cleared = append(cleared, Obj{
			"name": img.Name, "region": img.Region, "digest": Obj{"sha256": d},
			"provenance": envRD(bundle, S(conf, "provenance")), "signer": S(conf, "signer"),
		})
	}
	dir := filepath.Join(bundle, "artifacts", ProvisioningDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	jobRD, err := fileRD(job.Path, "")
	if err != nil {
		return err
	}
	gate := Obj{
		"job":       Obj{"id": job.ID, "file": jobRD},
		"station":   S(station, "station"),
		"checkedAt": Now(),
		"images":    cleared,
	}
	if err := WriteJSON(filepath.Join(dir, gateName(job.ID)), gate); err != nil {
		return err
	}
	fmt.Printf("gate: job %s cleared, %d image(s) match their provenance\n", job.ID, len(cleared))
	return nil
}

// The station log

type logRow struct {
	Line                            int
	Time                            time.Time
	Unit, Op, Target, Value, Result string
	raw                             []string
}

type stationLog struct {
	header []string
	rows   []logRow
}

// readLog reads the station log through the profile.
func readLog(export string, profile Obj) (*stationLog, error) {
	path := filepath.Join(export, S(profile, "log", "file"))
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	if d := S(profile, "log", "delimiter"); d != "" {
		r.Comma = []rune(d)[0]
	}
	r.Comment = '#'
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("%s: no header: %v", path, err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}
	idx := map[string]int{}
	for _, k := range []string{"time", "unit", "op", "target", "value", "result"} {
		name := S(profile, "log", "columns", k)
		i, ok := col[name]
		if !ok {
			return nil, fmt.Errorf("%s: no column %q (profile log.columns.%s)", path, name, k)
		}
		idx[k] = i
	}
	log := &stationLog{header: header}
	layout := S(profile, "log", "timeLayout")
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		line, _ := r.FieldPos(0)
		ts, err := time.Parse(layout, strings.TrimSpace(rec[idx["time"]]))
		if err != nil {
			return nil, fmt.Errorf("%s line %d: time %q does not match %s", path, line, rec[idx["time"]], layout)
		}
		log.rows = append(log.rows, logRow{
			Line: line, Time: ts, raw: rec,
			Unit: strings.TrimSpace(rec[idx["unit"]]), Op: strings.TrimSpace(rec[idx["op"]]),
			Target: strings.TrimSpace(rec[idx["target"]]), Value: strings.TrimSpace(rec[idx["value"]]),
			Result: strings.TrimSpace(rec[idx["result"]]),
		})
	}
	return log, nil
}

// session is a unit's last session, from its last begin row, and how many sessions it had.
func (l *stationLog) session(unit, begin string) ([]logRow, int) {
	var rows []logRow
	attempts := 0
	for _, r := range l.rows {
		if r.Unit != unit {
			continue
		}
		if r.Op == begin {
			attempts++
			rows = nil
		}
		rows = append(rows, r)
	}
	return rows, attempts
}

func (l *stationLog) units() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range l.rows {
		if r.Unit != "" && !seen[r.Unit] {
			seen[r.Unit] = true
			out = append(out, r.Unit)
		}
	}
	return out
}

// csvRows renders the header and rows as the station wrote them, with the profile's delimiter.
func (l *stationLog) csvRows(profile Obj, rows []logRow) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if d := S(profile, "log", "delimiter"); d != "" {
		w.Comma = []rune(d)[0]
	}
	if err := w.Write(l.header); err != nil {
		return nil, err
	}
	for _, r := range rows {
		if err := w.Write(r.raw); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// Fuse values

func fuseValue(field, raw, typ string) (any, error) {
	switch typ {
	case "", "string":
		return raw, nil
	case "hex":
		v := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X"))
		if !hexDigits.MatchString(v) {
			return nil, fmt.Errorf("fuse %s: %q is not hex", field, raw)
		}
		return v, nil
	case "int":
		n, err := strconv.ParseInt(raw, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("fuse %s: %q is not an integer", field, raw)
		}
		return n, nil
	case "bool":
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "on":
			return true, nil
		case "0", "false", "no", "off":
			return false, nil
		}
		return nil, fmt.Errorf("fuse %s: %q is not a boolean", field, raw)
	}
	return nil, fmt.Errorf("fuse %s: unknown type %q", field, typ)
}

// keyMaterial matches what looks like a secret value rather than a key id:
// a run of 32 or more hex digits, or of 43 or more base64 characters.
var keyMaterial = regexp.MustCompile(`[0-9A-Fa-f]{32,}|[A-Za-z0-9+/]{43,}={0,2}`)

// The adapter

// ProvisionAdapt reads a station export and signs one fw-provisioning record
// for every unit of the shipped lot, from that unit's last session in the
// log. It refuses, signing nothing, an export it cannot read as the profile
// describes, one that logs a secret's value, and one that leaves a unit of
// the lot out. A unit whose operations fail a check gets a record with that
// check failed, as the station logged it, and the adapter then exits with an
// error.
func ProvisionAdapt(bundle, profilePath, stationPath, export, keyRef string) error {
	profile, err := ReadStationProfile(profilePath)
	if err != nil {
		return err
	}
	station, err := ReadStationFile(stationPath)
	if err != nil {
		return err
	}
	job, err := readJob(export, profile)
	if err != nil {
		return err
	}
	log, err := readLog(export, profile)
	if err != nil {
		return err
	}
	if job.Lot != "" && job.Lot != S(station, "lotId") {
		return fmt.Errorf("job %s is for lot %s, the station file for lot %s", job.ID, job.Lot, S(station, "lotId"))
	}
	art := filepath.Join(bundle, "artifacts")
	units, err := ReadUnits(filepath.Join(art, "shipped-lot.txt"))
	if err != nil {
		return err
	}
	final, err := releasedSubject(bundle)
	if err != nil {
		return err
	}
	trust, err := LoadTrustRoot(filepath.Join(bundle, "trust-root.json"))
	if err != nil {
		return err
	}
	signer, err := stationSigner(keyRef)
	if err != nil {
		return err
	}

	// Refuse the whole export before signing anything.
	secret := setOf(Strs(station, "secrets"))
	for _, r := range log.rows {
		switch {
		case isOp(profile, r, "fuseWrite", "fuseRead") && secret[r.Target]:
			return failf("%s line %d: the log holds a value for secret field %s; refusing to sign from it", S(profile, "log", "file"), r.Line, r.Target)
		case isOp(profile, r, "keyInject", "keyGenerate") && keyMaterial.MatchString(r.Value):
			return failf("%s line %d: %s holds what looks like key material, not a key id; refusing to sign from it", S(profile, "log", "file"), r.Line, r.Target)
		}
	}
	inLot := setOf(units)
	for _, u := range log.units() {
		if !inLot[u] {
			fmt.Printf("adapt: %s is in the station log but not in the shipped lot; no record\n", u)
		}
	}
	for _, u := range units {
		if rows, _ := log.session(u, S(profile, "ops", "begin")); len(rows) == 0 {
			return failf("the station export has no session for %s, a unit of the shipped lot", u)
		}
	}

	dir := filepath.Join(art, ProvisioningDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	jobCopy := filepath.Join(dir, fileSlug(job.ID)+"-"+filepath.Base(job.Path))
	if err := copyFile(job.Path, jobCopy); err != nil {
		return err
	}
	jobRD, err := fileRD(jobCopy, ProvisioningDir+"/"+filepath.Base(jobCopy))
	if err != nil {
		return err
	}
	gatePath := filepath.Join(dir, gateName(job.ID))
	gate, gateErr := ReadObj(gatePath)
	var gateRD Obj
	if gateErr == nil {
		gateRD, _ = fileRD(gatePath, ProvisioningDir+"/"+gateName(job.ID))
	}

	a := &adapter{
		bundle: bundle, export: export, profile: profile, station: station, job: job, log: log,
		trust: trust, gate: gate, gateErr: gateErr, jobRD: jobRD, gateRD: gateRD,
		design: Obj{"name": final["name"], "digest": final["digest"], "release": envRD(bundle, AttName("release"))},
	}
	var failedUnits []string
	for _, u := range units {
		pred, subject, err := a.unit(u)
		if err != nil {
			return err
		}
		stmt, err := statement([]Obj{subject}, FWProvisioning, pred)
		if err != nil {
			return err
		}
		if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", ProvAtt(u))); err != nil {
			return err
		}
		if failed := failedChecks(Objs(pred, "hwProvision", "checks")); len(failed) > 0 {
			failedUnits = append(failedUnits, u+" ("+strings.Join(failed, ", ")+")")
		}
	}
	if len(failedUnits) > 0 {
		return fmt.Errorf("adapt: %s failed (recorded in the attestations)", strings.Join(failedUnits, "; "))
	}
	fmt.Printf("adapt: %s job %s, %d records signed from the station's export\n", S(profile, "model"), job.ID, len(units))
	return nil
}

type adapter struct {
	bundle, export         string
	profile, station, gate Obj
	job                    *stationJob
	log                    *stationLog
	trust                  *TrustRoot
	gateErr                error
	jobRD, gateRD, design  Obj
}

func (a *adapter) is(r logRow, names ...string) bool { return isOp(a.profile, r, names...) }

// unit builds one unit's record from its last session.
func (a *adapter) unit(unit string) (Obj, Obj, error) {
	rows, attempts := a.log.session(unit, S(a.profile, "ops", "begin"))
	pass := S(a.profile, "log", "pass")
	art := filepath.Join(a.bundle, "artifacts")

	// This unit's rows, kept by digest, so the record points at what the station logged.
	unitLog, err := a.log.csvRows(a.profile, rows)
	if err != nil {
		return nil, nil, err
	}
	logName := ProvisioningDir + "/" + unit + ".log.csv"
	if err := os.WriteFile(filepath.Join(art, logName), unitLog, 0o644); err != nil {
		return nil, nil, err
	}
	logRD := rd(logName, sha256Bytes(unitLog))

	allPassed := a.is(rows[len(rows)-1], "end")
	var firstWrite time.Time
	for _, r := range rows {
		if r.Result != pass {
			allPassed = false
		}
		if a.is(r, "program", "fuseWrite", "keyInject", "keyGenerate") && firstWrite.IsZero() {
			firstWrite = r.Time
		}
	}

	// Images: each one programmed, and the readback the station dumped after it.
	gateOK, gateDetail := a.gateCovers(firstWrite)
	byRegion := map[string]jobImage{}
	for _, img := range a.job.Images {
		byRegion[img.Region] = img
	}
	var images, deps []Obj
	readbackOK := true
	programmed := map[string]int{}
	for i, r := range rows {
		if !a.is(r, "program") {
			continue
		}
		img, ok := byRegion[r.Target]
		if !ok {
			return nil, nil, failf("%s line %d: %s programs region %s, which job %s does not load", S(a.profile, "log", "file"), r.Line, unit, r.Target, a.job.ID)
		}
		if _, dup := programmed[img.Region]; dup {
			continue
		}
		programmed[img.Region] = i
		conf := O(a.station, "images", img.Name)
		if conf == nil {
			return nil, nil, failf("job %s loads %s, which the station file does not list", a.job.ID, img.Name)
		}
		var readback Obj
		for _, v := range rows[i+1:] {
			if !a.is(v, "verify") || v.Target != img.Region {
				continue
			}
			readback = nil
			if v.Result == pass {
				if p, err := insideExport(a.export, v.Value); err == nil {
					readback = fileDigest(p)
				}
			}
		}
		if readback == nil || S(readback, "sha256") != img.SHA256 || r.Result != pass {
			readbackOK = false
		}
		images = append(images, Obj{
			"name": img.Name, "role": get(conf, "role"), "storage": get(conf, "storage"),
			"digest": Obj{"sha256": img.SHA256}, "readback": readback, "provenanceVerified": gateOK,
		})
		deps = append(deps, envRD(a.bundle, S(conf, "provenance")), rd(img.Name, img.SHA256))
	}
	if len(programmed) != len(a.job.Images) {
		readbackOK = false // the session left out an image the job loads
	}

	// Fuses: every value written, and what the station read back after writing it.
	types := O(a.station, "fuseTypes")
	written, read := Obj{}, Obj{}
	writtenAt := map[string]int{}
	fuseOK := true
	for i, r := range rows {
		switch {
		case a.is(r, "fuseWrite"):
			v, err := fuseValue(r.Target, r.Value, S(types, r.Target))
			if err != nil {
				return nil, nil, failf("%s line %d: %v", S(a.profile, "log", "file"), r.Line, err)
			}
			written[r.Target] = v
			writtenAt[r.Target] = i
			if r.Result != pass {
				fuseOK = false
			}
		case a.is(r, "fuseRead"):
			v, err := fuseValue(r.Target, r.Value, S(types, r.Target))
			if err != nil {
				return nil, nil, failf("%s line %d: %v", S(a.profile, "log", "file"), r.Line, err)
			}
			if at, ok := writtenAt[r.Target]; ok && i > at && r.Result == pass {
				read[r.Target] = v
			}
		}
	}
	for k, v := range written {
		if !jsonEqual(read[k], v) {
			fuseOK = false
		}
	}
	for k := range types {
		if _, ok := written[k]; !ok {
			fuseOK = false // a field of the part's fuse map was never burned
		}
	}

	// Secrets, by key id and origin only.
	secrets := []Obj{}
	for _, r := range rows {
		origin := ""
		switch {
		case a.is(r, "keyInject"):
			if S(a.station, "hsm") == "" {
				return nil, nil, fmt.Errorf("%s injects %s, but the station file names no hsm", unit, r.Target)
			}
			origin = "injected by " + S(a.station, "hsm")
		case a.is(r, "keyGenerate"):
			origin = "generated-on-die"
		default:
			continue
		}
		secrets = append(secrets, Obj{"field": r.Target, "keyId": r.Value, "origin": origin})
	}

	checks := []Obj{
		check("image-provenance-verified", gateOK, gateDetail),
		check("image-readback", readbackOK, ""),
		check("fuse-readback", fuseOK, ""),
	}

	// Identity: the CSR the part exported and the certificate the CA returned.
	subject := rd("urn:hslsa:unit:"+unit, sha256Bytes([]byte(unit)))
	identity := Obj{}
	if idc := O(a.station, "identity"); idc != nil {
		csrDER, certDER, err := a.identityFiles(unit, rows)
		if err != nil {
			return nil, nil, err
		}
		csrName, certName := "identity/"+unit+".csr.der", "identity/"+unit+".idevid.der"
		if err := os.MkdirAll(filepath.Join(art, "identity"), 0o755); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(filepath.Join(art, csrName), csrDER, 0o644); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(filepath.Join(art, certName), certDER, 0o644); err != nil {
			return nil, nil, err
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return nil, nil, failf("%s: the exported CSR does not parse: %v", unit, err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, nil, failf("%s: the IDevID certificate does not parse: %v", unit, err)
		}
		csrKey, err := spkiDigest(csr.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		certKey, _ := spkiDigest(cert.PublicKey)
		endorsed := false
		for _, k := range a.trust.Roles[S(idc, "caRole")] {
			endorsed = endorsed || signedBy(cert, k.Public)
		}
		checks = append(checks,
			check("csr-self-signature", csr.CheckSignature() == nil, ""),
			check("certificate-matches-csr", certKey == csrKey, ""),
			check("certificate-endorsed", endorsed, "signed by a key the trust root lists as "+S(idc, "caRole")),
		)
		csrRD, certRD := rd(csrName, sha256Bytes(csrDER)), rd(certName, sha256Bytes(certDER))
		deps = append(deps, csrRD, certRD)
		identity = Obj{
			"scheme":          get(idc, "scheme"),
			"ueid":            written[S(idc, "ueidFuse")],
			"idevidPublicKey": Obj{"sha256": csrKey},
			"certificate":     certRD,
			"endorsingCa":     cert.Issuer.CommonName,
		}
		subject = rd("urn:hslsa:unit:"+unit, csrKey)
	}
	if lc := O(a.station, "lifecycle"); lc != nil {
		checks = append(checks, check("lifecycle-production",
			jsonEqual(written[S(lc, "fuse")], S(lc, "production")) && Truthy(written[S(lc, "debugLock")]), ""))
	}
	checks = append(checks, check("station-log-passed", allPassed, fmt.Sprintf("last of %d session(s)", attempts)))

	readDigest := Obj{"sha256": canonicalDigest(read)}
	deps = append(deps, a.jobRD, logRD)
	export := Obj{"model": get(a.profile, "model"), "job": Obj{"id": a.job.ID, "file": a.jobRD}, "log": logRD, "sessions": attempts}
	if a.gateRD != nil {
		deps = append(deps, a.gateRD)
		export["gate"] = a.gateRD
	}
	pred := Obj{
		"buildDefinition": Obj{
			"buildType":            ProvisionType,
			"externalParameters":   Obj{"unit": unit, "lotId": S(a.station, "lotId"), "stage": S(a.station, "stage"), "job": a.job.ID},
			"resolvedDependencies": deps,
		},
		"runDetails": Obj{
			"builder":  Obj{"id": "urn:hslsa:site:" + slug(S(a.station, "site", "name"))},
			"metadata": Obj{"invocationId": "provision:" + unit, "startedOn": rows[0].Time.UTC().Format(time.RFC3339), "finishedOn": rows[len(rows)-1].Time.UTC().Format(time.RFC3339)},
		},
		"hwProvision": Obj{
			"station":      S(a.station, "station"),
			"site":         get(a.station, "site"),
			"unit":         "urn:hslsa:unit:" + unit,
			"lot":          "urn:hslsa:lot:" + S(a.station, "lotId"),
			"designRef":    a.design,
			"images":       images,
			"fuses":        written,
			"fuseReadback": readDigest,
			"secrets":      secrets,
			"identity":     identity,
			"export":       export,
			"checks":       checks,
		},
	}
	return pred, subject, nil
}

// gateCovers says whether the cleared job is the job that ran and was cleared before the unit's first write.
func (a *adapter) gateCovers(firstWrite time.Time) (bool, string) {
	if a.gateErr != nil {
		return false, "job " + a.job.ID + " was never cleared at the gate"
	}
	if !jsonEqual(get(a.gate, "job", "file", "digest"), get(a.jobRD, "digest")) {
		return false, "the job that ran is not the job the gate cleared"
	}
	at, err := time.Parse(time.RFC3339, S(a.gate, "checkedAt"))
	if err != nil || firstWrite.IsZero() || firstWrite.Before(at) {
		return false, "the station wrote to the part before the gate cleared the job"
	}
	cleared := map[string]bool{}
	for _, c := range Objs(a.gate, "images") {
		cleared[S(c, "name")+"@"+S(c, "digest", "sha256")] = true
	}
	for _, img := range a.job.Images {
		if !cleared[img.Name+"@"+img.SHA256] {
			return false, "the gate did not clear " + img.Name
		}
	}
	return true, "cleared at " + S(a.gate, "checkedAt") + ", before the first write"
}

// identityFiles reads the CSR and certificate the session's rows name.
func (a *adapter) identityFiles(unit string, rows []logRow) ([]byte, []byte, error) {
	files := map[string]string{}
	for _, r := range rows {
		for _, op := range []string{"csr", "certificate"} {
			if a.is(r, op) && r.Result == S(a.profile, "log", "pass") {
				files[op] = r.Value
			}
		}
	}
	var out [2][]byte
	for i, op := range []string{"csr", "certificate"} {
		if files[op] == "" {
			return nil, nil, failf("%s: the station log has no %s row for the unit's identity", unit, op)
		}
		p, err := insideExport(a.export, files[op])
		if err != nil {
			return nil, nil, failf("%s: %v", unit, err)
		}
		if out[i], err = os.ReadFile(p); err != nil {
			return nil, nil, failf("%s: %v", unit, err)
		}
	}
	return out[0], out[1], nil
}
