# Documentation website

The website shows the repository's documentation as one searchable site: the README as its home page, the specification, the concept pages, the worked examples, the supplier adapters, the pilot kit, a command reference for `hslsa` and the HBOM schema.

It holds no text of its own. `site/gen` turns the markdown already in the repository into Hugo pages when the site is built, so a change to a document changes the site and nothing else needs editing. A markdown file added under `docs/`, `spec/` or `pilot/` must be added to the pages list in [`gen/main.go`](gen/main.go), or the build fails; that is also where a page's section and its shorter sidebar title are set.

## Building and reading it

```sh
site/build.sh          # writes site/public; open site/public/index.html in a browser
site/build.sh serve    # the same, then serves it at http://localhost:1313
```

The script needs Go and curl. It downloads Hugo and mermaid (for the diagrams) once into `site/.cache`, at the versions pinned in the script and checked against their sha256 sums, builds `hslsa` for the command reference, generates the pages, runs Hugo, and then checks that every link and anchor inside the built site resolves. Outside Linux on x86-64, install the pinned Hugo version yourself first.

The built site works opened straight from disk: links are relative, pages end in `.html`, and the search index is a script rather than a file the page fetches. Search, the light and dark switch, and the diagrams all run in the browser with nothing fetched from elsewhere except the IBM Plex fonts from Google Fonts, which fall back to system fonts offline.

## In CI

[`docs-site.yml`](../.github/workflows/docs-site.yml) runs `site/build.sh` on pushes to `main` and pull requests that touch any markdown, the site, the HBOM schema or the tool's commands, and uploads the built site as the `docs-site` artifact for 30 days. To read it, open the run, download `docs-site`, unzip it and open `index.html`.

## Publishing

Every push to `main` that changes the site's sources also publishes it on GitHub Pages, at <https://horiodino.github.io/hw-slsa/>, where anyone can read it and search engines can index it. Pull requests only build and check it. The deploy job needs Pages turned on once: Settings → Pages → Source: **GitHub Actions**. To keep the site out of search engines, set `noindex = true` in [`hugo.toml`](hugo.toml).

## Layout

| Path | What it is |
| --- | --- |
| `gen/main.go` | The pages list, the page generator and the link checker |
| `hugo.toml` | Hugo settings |
| `layouts/` | Page templates, and render hooks for headings, tables and mermaid diagrams |
| `static/css/site.css`, `static/js/site.js` | Styles (light and dark), search, the theme switch and the diagram setup |
| `build.sh` | Builds and checks the site |

`content/`, `public/`, `.cache/` and `static/js/mermaid.min.js` are made by the build and are not committed.
