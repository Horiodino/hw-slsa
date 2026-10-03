// Command gen builds the documentation website's content from the markdown
// already in the repository, so the site never holds a second copy that can
// drift from it.
//
//	go run ./site/gen -hslsa bin/hslsa      # writes site/content
//	hugo --source site                      # writes site/public
//	go run ./site/gen -check site/public    # every internal link and anchor resolves
//
// Every page comes from one file in the pages list below. A markdown file
// under docs/, spec/ or pilot/ that the list leaves out is an error, so a new
// document cannot be forgotten. Relative links between listed files become
// links between pages; links to anything else in the repository go to the
// file on GitHub. The command reference is generated from hslsa's own help.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"html"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const repoURL = "https://github.com/Horiodino/hw-slsa"

type section struct {
	key, title, intro string
	weight            int
}

// page is one page of the site. src is a repository path; out is the path
// under content/. A page whose out is <section>/_index.md is the section's
// own page.
type page struct {
	src, out string
	nav      string // shorter title for the sidebar, if the document's is long
}

var sections = []section{
	{"spec", "Specification", "The framework itself: tracks, levels, the attestation chain, the records and how a buyer checks them.", 10},
	{"concepts", "Concepts", "The ideas the specification relies on, explained one at a time.", 20},
	{"examples", "Worked examples", "Real open-source designs taken through the chain end to end, as CI runs them.", 30},
	{"adapters", "Supplier adapters", "How existing supplier systems (EDA tools, MES and test data, provisioning stations, HSMs) produce signed records without changing how they work.", 40},
	{"pilot", "Pilot kit", "", 50},
	{"reference", "Reference", "The command line tool, schemas and formats.", 60},
	{"project", "Project", "Where the project stands, where it is going, and how it is released.", 70},
}

var pages = []page{
	{src: "README.md", out: "_index.md"},

	{src: "spec/hslsa-v0.1.md", out: "spec/hslsa-v0.1.md", nav: "HSLSA v0.1"},
	{src: "spec/nist-ir-8536-profile.md", out: "spec/nist-ir-8536-profile.md", nav: "NIST IR 8536 profile"},

	{src: "docs/levels.md", out: "concepts/levels.md", nav: "Levels L3 and L4"},
	{src: "docs/selective-disclosure.md", out: "concepts/selective-disclosure.md"},
	{src: "docs/proxy-signing.md", out: "concepts/proxy-signing.md", nav: "Proxy signing"},
	{src: "docs/simulated-hardware.md", out: "concepts/simulated-hardware.md", nav: "Simulated hardware"},

	{src: "docs/e2e-test.md", out: "examples/e2e-test.md"},
	{src: "docs/board-example.md", out: "examples/board-example.md"},
	{src: "docs/openlane2-flow.md", out: "examples/openlane2-flow.md", nav: "OpenLane 2 flow"},
	{src: "openlane2/overlay/README.md", out: "examples/openlane2-overlay.md", nav: "OpenLane 2 script overlay"},
	{src: "docs/caliptra-e2e.md", out: "examples/caliptra-e2e.md", nav: "Caliptra example"},
	{src: "docs/fpga-board-example.md", out: "examples/fpga-board-example.md", nav: "FPGA board example"},

	{src: "adapters/eda-tcl/README.md", out: "adapters/eda-tcl.md"},
	{src: "docs/mes-stdf-adapter.md", out: "adapters/mes-stdf-adapter.md", nav: "MES and STDF adapter"},
	{src: "docs/provisioning-adapter.md", out: "adapters/provisioning-adapter.md"},
	{src: "docs/hsm-signing.md", out: "adapters/hsm-signing.md", nav: "HSM signing"},

	{src: "pilot/README.md", out: "pilot/_index.md", nav: "Pilot kit"},
	{src: "pilot/buyer.md", out: "pilot/buyer.md", nav: "The buyer's steps"},
	{src: "pilot/supplier.md", out: "pilot/supplier.md", nav: "The suppliers' steps"},
	{src: "pilot/vendor.md", out: "pilot/vendor.md", nav: "For a chip vendor"},
	{src: "pilot/agreement.md", out: "pilot/agreement.md", nav: "What the parties settle"},

	// reference/cli.md and reference/hbom-schema.md are generated below.
	{src: "hbom/formats/README.md", out: "reference/sbom-formats.md"},
	{src: "docs/rego-policies.md", out: "reference/rego-policies.md", nav: "Buyer policies in Rego"},

	{src: "docs/roadmap.md", out: "project/roadmap.md", nav: "Roadmap"},
	{src: "docs/viability.md", out: "project/viability.md", nav: "Viability assessment"},
	{src: "docs/release.md", out: "project/release.md", nav: "Releases and the image"},
	{src: "SECURITY.md", out: "project/security.md", nav: "Reporting security problems"},
}

// covered are the directories whose every markdown file must be a page.
var covered = []string{"docs", "spec", "pilot"}

func main() {
	root := flag.String("root", ".", "repository root")
	out := flag.String("out", "site/content", "content directory to write (emptied first)")
	bin := flag.String("hslsa", "", "hslsa binary, for the command reference (required unless -check)")
	check := flag.String("check", "", "instead of generating, check every internal link and anchor in this built site")
	flag.Parse()
	var err error
	if *check != "" {
		err = checkSite(*check)
	} else if *bin == "" {
		err = errors.New("-hslsa is required")
	} else {
		var abs string
		if abs, err = filepath.Abs(*bin); err == nil {
			err = generate(*root, *out, abs)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func generate(root, out, bin string) error {
	if err := checkCovered(root); err != nil {
		return err
	}
	byPath := map[string]string{} // repository path -> content path
	for _, p := range pages {
		byPath[p.src] = p.out
	}
	if err := os.RemoveAll(out); err != nil {
		return err
	}
	weight := map[string]int{}
	for _, p := range pages {
		raw, err := os.ReadFile(filepath.Join(root, p.src))
		if err != nil {
			return err
		}
		title, body := splitTitle(string(raw))
		if title == "" {
			return fmt.Errorf("%s: no level 1 heading to take the title from", p.src)
		}
		body, err = rewriteLinks(root, p.src, body, byPath)
		if err != nil {
			return err
		}
		sec := path.Dir(p.out)
		weight[sec] += 10
		fm := frontMatter{title: title, nav: p.nav, weight: weight[sec], description: describe(body), source: p.src}
		if path.Base(p.out) == "_index.md" && sec != "." {
			fm.weight = sectionByKey(sec).weight
		}
		if err := writePage(filepath.Join(out, p.out), fm, body); err != nil {
			return err
		}
	}
	for _, s := range sections {
		if findOut(s.key+"/_index.md") != "" {
			continue
		}
		fm := frontMatter{title: s.title, weight: s.weight, description: s.intro}
		if err := writePage(filepath.Join(out, s.key, "_index.md"), fm, s.intro+"\n"); err != nil {
			return err
		}
	}
	cli, err := cliReference(bin)
	if err != nil {
		return err
	}
	if err := writePage(filepath.Join(out, "reference/cli.md"),
		frontMatter{title: "hslsa command reference", nav: "hslsa commands", weight: 1, source: "tools/hslsa/cmd/hslsa/main.go",
			description: "Every hslsa command and its flags, generated from the tool's own help."}, cli); err != nil {
		return err
	}
	schema, err := os.ReadFile(filepath.Join(root, "hbom/hbom-predicate-v0.1.schema.json"))
	if err != nil {
		return err
	}
	return writePage(filepath.Join(out, "reference/hbom-schema.md"),
		frontMatter{title: "HBOM predicate schema", weight: 2, source: "hbom/hbom-predicate-v0.1.schema.json",
			description: "The JSON Schema (2020-12) for the HBOM predicate, as committed."},
		"The JSON Schema (2020-12) that `hslsa validate-hbom` checks HBOM statements against. "+
			"The specification's [HBOM section]({{< page \"/spec/hslsa-v0.1.md\" >}}#hardware-bill-of-materials) explains each field, "+
			"and the [chip]("+repoURL+"/blob/main/hbom/picosoc-sky130.hbom.intoto.json) and "+
			"[board]("+repoURL+"/blob/main/hbom/picosoc-devboard.hbom.intoto.json) examples show it filled in.\n\n"+
			"```json\n"+strings.TrimRight(string(schema), "\n")+"\n```\n")
}

// findOut returns the source path whose page is out, or "".
func findOut(out string) string {
	for _, p := range pages {
		if p.out == out {
			return p.src
		}
	}
	return ""
}

func sectionByKey(k string) section {
	for _, s := range sections {
		if s.key == k {
			return s
		}
	}
	panic("no section " + k)
}

func checkCovered(root string) error {
	listed := map[string]bool{}
	for _, p := range pages {
		listed[p.src] = true
	}
	var missing []string
	for _, dir := range covered {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			if !listed[filepath.ToSlash(rel)] {
				missing = append(missing, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("not on the site, add to the pages list in site/gen/main.go: %s", strings.Join(missing, ", "))
	}
	return nil
}

// splitTitle takes the first level 1 heading out of a document.
func splitTitle(doc string) (string, string) {
	lines := strings.Split(doc, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "# ") {
			return strings.TrimSpace(l[2:]), strings.TrimLeft(strings.Join(append(lines[:i:i], lines[i+1:]...), "\n"), "\n")
		}
		if strings.TrimSpace(l) != "" {
			break
		}
	}
	return "", doc
}

var (
	linkRe   = regexp.MustCompile(`\]\(([^()\s]+)\)`)
	fenceRe  = regexp.MustCompile("^\\s*(```|~~~)")
	schemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
)

// rewriteLinks points each relative link at its page on the site, or at the
// file on GitHub when the site has no page for it.
func rewriteLinks(root, src, body string, byPath map[string]string) (string, error) {
	var bad []string
	inFence := false
	lines := strings.Split(body, "\n")
	for i, l := range lines {
		if fenceRe.MatchString(l) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		lines[i] = linkRe.ReplaceAllStringFunc(l, func(m string) string {
			target := m[2 : len(m)-1]
			if strings.HasPrefix(target, "#") || schemeRe.MatchString(target) {
				return m
			}
			file, frag, _ := strings.Cut(target, "#")
			if frag != "" {
				frag = "#" + frag
			}
			p := path.Clean(path.Join(path.Dir(src), file))
			if out, ok := byPath[p]; ok {
				return fmt.Sprintf(`]({{< page %q >}}%s)`, "/"+out, frag)
			}
			fi, err := os.Stat(filepath.Join(root, p))
			if err != nil {
				bad = append(bad, target)
				return m
			}
			kind := "blob"
			if fi.IsDir() {
				kind = "tree"
			}
			return fmt.Sprintf("](%s/%s/main/%s%s)", repoURL, kind, p, frag)
		})
	}
	if len(bad) > 0 {
		return "", fmt.Errorf("%s: links to files that do not exist: %s", src, strings.Join(bad, ", "))
	}
	return strings.Join(lines, "\n"), nil
}

var (
	mdLinkRe  = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	mdMarksRe = regexp.MustCompile("[*_`]")
)

// describe is the document's first paragraph as plain text, for section
// listings, search results and the meta description.
func describe(body string) string {
	inFence := false
	var para []string
	for _, l := range strings.Split(body, "\n") {
		t := strings.TrimSpace(l)
		if fenceRe.MatchString(l) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if t == "" {
			if len(para) > 0 {
				break
			}
			continue
		}
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "|") || strings.HasPrefix(t, "<") || strings.HasPrefix(t, "- ") {
			if len(para) > 0 {
				break
			}
			continue
		}
		para = append(para, t)
	}
	s := strings.Join(para, " ")
	s = mdLinkRe.ReplaceAllString(s, "$1")
	s = mdMarksRe.ReplaceAllString(s, "")
	if len(s) > 240 {
		cut := strings.LastIndex(s[:240], " ")
		s = s[:cut] + "…"
	}
	return s
}

type frontMatter struct {
	title, nav, description, source string
	weight                          int
}

func writePage(file string, fm frontMatter, body string) error {
	var b strings.Builder
	b.WriteString("+++\n")
	fmt.Fprintf(&b, "title = %s\n", strconv.Quote(fm.title))
	if fm.nav != "" {
		fmt.Fprintf(&b, "linkTitle = %s\n", strconv.Quote(fm.nav))
	}
	if fm.description != "" {
		fmt.Fprintf(&b, "description = %s\n", strconv.Quote(fm.description))
	}
	fmt.Fprintf(&b, "weight = %d\n", fm.weight)
	if fm.source != "" {
		fmt.Fprintf(&b, "[params]\nsource = %s\n", strconv.Quote(fm.source))
	}
	b.WriteString("+++\n\n")
	b.WriteString(body)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	return os.WriteFile(file, []byte(b.String()), 0o644)
}

var subsRe = regexp.MustCompile(`expected one of: (.+)`)

// cliReference documents every command and subcommand from hslsa's own help.
func cliReference(bin string) (string, error) {
	top, _ := run(bin, "help")
	var names []string
	descs := map[string]string{}
	inList := false
	for _, l := range strings.Split(top, "\n") {
		if strings.HasPrefix(l, "commands:") {
			inList = true
			continue
		}
		if !inList || strings.TrimSpace(l) == "" {
			continue
		}
		name, desc, _ := strings.Cut(strings.TrimSpace(l), " ")
		names = append(names, name)
		descs[name] = strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(strings.TrimSpace(desc))
	}
	if len(names) == 0 {
		return "", fmt.Errorf("%s help listed no commands:\n%s", bin, top)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("Generated from `hslsa help` and each command's `-h` when the site was built. ")
	b.WriteString("Build the tool with `go build -o bin/hslsa ./tools/hslsa/cmd/hslsa`, or run it from the pilot kit's container image. ")
	b.WriteString("A check that fails exits with status 1 and a line starting `FAILED:`; a command line mistake exits with status 2.\n\n")
	b.WriteString("| Command | What it does |\n| --- | --- |\n")
	for _, n := range names {
		fmt.Fprintf(&b, "| [`%s`](#%s) | %s |\n", n, n, descs[n])
	}
	for _, n := range names {
		fmt.Fprintf(&b, "\n## %s\n\n%s.\n\n", n, upperFirst(descs[n]))
		help, _ := run(bin, n, "-h")
		if m := subsRe.FindStringSubmatch(help); m != nil {
			for _, sub := range strings.Split(m[1], ", ") {
				sub = strings.TrimSpace(sub)
				h, _ := run(bin, n, sub, "-h")
				fmt.Fprintf(&b, "### %s %s\n\n", n, sub)
				b.WriteString(usageBlock(h))
			}
			continue
		}
		b.WriteString(usageBlock(help))
	}
	return b.String(), nil
}

func usageBlock(h string) string {
	h = strings.TrimRight(h, "\n")
	if !strings.HasPrefix(h, "Usage of ") {
		return "Takes its inputs as arguments; see the examples that use it.\n\n"
	}
	return "```text\n" + h + "\n```\n\n"
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// run returns a command's combined output; hslsa writes help to stderr and
// exits non-zero for some of it, which is expected here.
func run(bin string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.Dir = os.TempDir()
	err := cmd.Run()
	return out.String(), err
}

var (
	attrRe = regexp.MustCompile(`\s(?:href|src)=(?:"([^"]*)"|([^\s"'>]+))`)
	idRe   = regexp.MustCompile(`\sid=(?:"([^"]*)"|([^\s"'>]+))`)
)

// checkSite fails on any link inside the built site to a page or an anchor
// that does not exist.
func checkSite(dir string) error {
	ids := map[string]map[string]bool{}
	docs := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		docs[p] = string(raw)
		ids[p] = map[string]bool{}
		for _, m := range idRe.FindAllStringSubmatch(string(raw), -1) {
			ids[p][html.UnescapeString(m[1]+m[2])] = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(docs) == 0 {
		return fmt.Errorf("no pages in %s", dir)
	}
	var bad []string
	files := make([]string, 0, len(docs))
	for p := range docs {
		files = append(files, p)
	}
	sort.Strings(files)
	links := 0
	for _, p := range files {
		for _, m := range attrRe.FindAllStringSubmatch(docs[p], -1) {
			u := html.UnescapeString(m[1] + m[2])
			if u == "" || schemeRe.MatchString(u) || strings.HasPrefix(u, "//") {
				continue
			}
			links++
			file, frag, _ := strings.Cut(u, "#")
			target := p
			if file != "" {
				if strings.HasPrefix(file, "/") {
					bad = append(bad, fmt.Sprintf("%s: %s is absolute, so it breaks when the site is opened from disk", p, u))
					continue
				}
				target = filepath.Join(filepath.Dir(p), filepath.FromSlash(file))
				if fi, err := os.Stat(target); err == nil && fi.IsDir() {
					bad = append(bad, fmt.Sprintf("%s: %s is a directory, which a browser opening the site from disk lists instead of showing its page", p, u))
					continue
				}
				if _, err := os.Stat(target); err != nil {
					bad = append(bad, fmt.Sprintf("%s: %s does not exist", p, u))
					continue
				}
			}
			if frag != "" && strings.HasSuffix(target, ".html") && !ids[target][frag] {
				bad = append(bad, fmt.Sprintf("%s: %s has no anchor #%s", p, u, frag))
			}
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%d broken links:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	fmt.Printf("%d pages, %d internal links, all resolve\n", len(docs), links)
	return nil
}
