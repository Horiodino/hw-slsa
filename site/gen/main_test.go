package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The repository's own docs are all on the site, and every page's source exists.
func TestPagesCoverRepository(t *testing.T) {
	if err := checkCovered("../.."); err != nil {
		t.Fatal(err)
	}
	for _, p := range pages {
		if _, err := os.Stat(filepath.Join("../..", p.src)); err != nil {
			t.Errorf("page source %s: %v", p.src, err)
		}
	}
}

func TestCoveredRefusesUnlistedDoc(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"docs/new-guide.md", "spec/x.txt", "pilot/notes.txt"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte("# New\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err := checkCovered(root)
	if err == nil || !strings.Contains(err.Error(), "docs/new-guide.md") || strings.Contains(err.Error(), "x.txt") {
		t.Fatalf("got %v, want an error naming docs/new-guide.md only", err)
	}
}

func TestRewriteLinks(t *testing.T) {
	byPath := map[string]string{"spec/hslsa-v0.1.md": "spec/hslsa-v0.1.md", "README.md": "_index.md"}
	body := strings.Join([]string{
		"See [the spec](../spec/hslsa-v0.1.md#threat-model), [home](../README.md) and [here](#local).",
		"The [tool](../tools/hslsa) and [schema](../hbom/hbom-predicate-v0.1.schema.json), or [SLSA](https://slsa.dev).",
		"```",
		"[not a link](../nowhere.md)",
		"```",
	}, "\n")
	got, err := rewriteLinks("../..", "docs/levels.md", body, byPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`[the spec]({{< page "/spec/hslsa-v0.1.md" >}}#threat-model)`,
		`[home]({{< page "/_index.md" >}})`,
		`[here](#local)`,
		"[tool](" + repoURL + "/tree/main/tools/hslsa)",
		"[schema](" + repoURL + "/blob/main/hbom/hbom-predicate-v0.1.schema.json)",
		"[SLSA](https://slsa.dev)",
		"[not a link](../nowhere.md)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
}

func TestRewriteLinksRefusesMissingFile(t *testing.T) {
	_, err := rewriteLinks("../..", "docs/levels.md", "[gone](no-such-file.md)", nil)
	if err == nil || !strings.Contains(err.Error(), "no-such-file.md") {
		t.Fatalf("got %v, want an error naming the missing file", err)
	}
}

func TestSplitTitleAndDescribe(t *testing.T) {
	title, body := splitTitle("# Proxy signing: suppliers that sign nothing\n\nA supplier that signs [nothing](x.md) can still `appear`.\nSecond line.\n\n## Next\n")
	if title != "Proxy signing: suppliers that sign nothing" {
		t.Errorf("title %q", title)
	}
	if strings.Contains(body, "# Proxy") {
		t.Errorf("title left in body: %q", body)
	}
	if d := describe(body); d != "A supplier that signs nothing can still appear. Second line." {
		t.Errorf("description %q", d)
	}
}
