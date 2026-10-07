# One entry point for everything this repository builds, checks, runs and
# releases. `make` alone lists the targets.
#
# Each target runs the commands of the CI job it names, in the same order, with
# the same tool versions. The downloaded tools' versions and sha256 sums are
# read from the workflows, so a change there is picked up here; the Ubuntu
# package pins are copied from them (APT_PACKAGES). What only the workflows do:
# upload artifacts, write job summaries and publish a release; `make release`
# pushes the tag that starts the release workflow.
#
# Needs GNU make 3.82 or later (on macOS, `brew install make` and run gmake),
# bash, Go at the go.mod toolchain, git, curl, jq and openssl. Each e2e target
# also needs its example's tools: `make deps-ubuntu` installs them on Ubuntu
# 24.04 the way the workflows do. The README's "Building and testing" section
# lists what each example needs.
#
# Private by design, like the workflows: every e2e target makes its keys during
# the run and deletes them when it ends, pass or fail, and nothing leaves this
# machine except through image-push and release.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
# Each recipe runs as one bash script. Inside one, no command may start with
# -, @ or +: make strips those from the start of every line, not only the
# first (a line continued with a backslash is left alone).
.ONESHELL:
# The e2e steps depend on each other's output under out/, so never in parallel.
.NOTPARALLEL:
.DEFAULT_GOAL := help
MAKEFLAGS += --no-builtin-rules

GO ?= go
# The example scripts run this binary; each builds its own when HSLSA is unset.
export HSLSA ?= $(CURDIR)/bin/hslsa
# The chain tests take longer than go test's default 10 minutes once the
# e2e bundles exist.
TEST_TIMEOUT ?= 60m
TOOLS := $(CURDIR)/bin/tools
KIT_DIR ?= out/kit
IMAGE ?= ghcr.io/horiodino/hw-slsa
IMAGE_ARCHES ?= amd64 arm64
# Where ciel enables the SKY130 PDK for the OpenLane example (ciel's default).
export PDK_ROOT ?= $(HOME)/.ciel

# Pinned versions and checksums, read from the workflows.
wf = $(shell sed -n 's/^  $(1): *"\{0,1\}\([^"]*\)"\{0,1\} *$$/\1/p' .github/workflows/$(2) | head -1)
SLSA_VERIFIER_VERSION := $(call wf,SLSA_VERIFIER_VERSION,hslsa-e2e.yml)
SLSA_VERIFIER_SHA256 := $(call wf,SLSA_VERIFIER_SHA256,hslsa-e2e.yml)
OPA_VERSION := $(call wf,OPA_VERSION,hslsa-e2e.yml)
OPA_SHA256 := $(call wf,OPA_SHA256,hslsa-e2e.yml)
CYCLONEDX_CLI_VERSION := $(call wf,CYCLONEDX_CLI_VERSION,hslsa-e2e.yml)
CYCLONEDX_CLI_SHA256 := $(call wf,CYCLONEDX_CLI_SHA256,hslsa-e2e.yml)
RUST_TOOLCHAIN := $(call wf,RUST_TOOLCHAIN,caliptra-e2e.yml)
CIEL_VERSION := $(call wf,CIEL_VERSION,openlane2-flow.yml)
GOVULNCHECK_VERSION := $(shell sed -n 's|.*govulncheck@\(v[0-9.]*\) .*|\1|p' .github/workflows/hslsa-e2e.yml | head -1)
$(foreach v,SLSA_VERIFIER_VERSION SLSA_VERIFIER_SHA256 OPA_VERSION OPA_SHA256 CYCLONEDX_CLI_VERSION \
  CYCLONEDX_CLI_SHA256 RUST_TOOLCHAIN CIEL_VERSION GOVULNCHECK_VERSION,\
  $(if $($(v)),,$(error $(v) not found in .github/workflows: this Makefile reads it from there)))

# The packages the workflows install on ubuntu-24.04, at the versions they pin:
# the examples' L3 policies pin these tools by digest.
APT_PACKAGES := yosys=0.33-5build2 iverilog=12.0-2build2 softhsm2 bubblewrap \
  nextpnr-ice40 fpga-icestorm fpga-icestorm-chipdb \
  gcc-riscv64-unknown-elf=13.2.0-11ubuntu1+12 binutils-riscv64-unknown-elf=2.42-1ubuntu1+6 \
  verilator jq openssl openssh-client git curl python3-venv

# slsa-verifier, OPA, the CycloneDX CLI and ciel: set one to your own binary's
# path, or `make tools` downloads the pinned release into bin/tools.
export SLSA_VERIFIER ?= $(TOOLS)/slsa-verifier-$(SLSA_VERIFIER_VERSION)
export OPA ?= $(TOOLS)/opa-$(OPA_VERSION)
CYCLONEDX ?= $(TOOLS)/cyclonedx-$(CYCLONEDX_CLI_VERSION)
CIEL ?= $(TOOLS)/ciel-$(CIEL_VERSION)/bin/ciel
# The ones this file downloads, leaving out any set to another path.
own = $(filter $(TOOLS)/%,$(1))

# What a release from here is called. VERSION is the v* tag at HEAD on a clean
# tree, otherwise dev-<commit>, with -dirty for uncommitted changes.
COMMIT := $(shell git rev-parse HEAD 2>/dev/null)
SOURCE_DATE_EPOCH := $(shell git log -1 --format=%ct HEAD 2>/dev/null)
ifeq ($(origin VERSION),undefined)
DIRTY := $(if $(shell git status --porcelain --untracked-files=no 2>/dev/null),-dirty)
VERSION := $(or $(if $(DIRTY),,$(shell git describe --tags --exact-match --match 'v*' HEAD 2>/dev/null)),dev-$(shell git rev-parse --short=12 HEAD 2>/dev/null)$(DIRTY))
endif
SPEC := $(firstword $(wildcard spec/hslsa-v*.md))
# As make-kit.sh reads it. In a variable, since make would count its "(".
revision_sed := s/.*revision \([0-9]*\) (.*/\1/p
SPEC_REVISION := $(shell sed -n '$(revision_sed)' $(SPEC) | head -1)
HOST_ARCH := $(shell $(GO) env GOARCH 2>/dev/null)
# The image to run after building: this machine's platform if built, else the first.
RUN_ARCH := $(firstword $(filter $(HOST_ARCH),$(IMAGE_ARCHES)) $(IMAGE_ARCHES))

# The image's OCI labels, as the release workflow sets them.
define image_labels
labels=(
  "org.opencontainers.image.source=https://github.com/Horiodino/hw-slsa"
  "org.opencontainers.image.revision=$(COMMIT)"
  "org.opencontainers.image.version=$(VERSION)"
  "org.opencontainers.image.licenses=Apache-2.0 AND CC-BY-4.0"
  "org.opencontainers.image.title=hslsa"
  "org.opencontainers.image.description=HSLSA reference tool: sign and verify hardware supply chain records"
)
endef

# Each test step sees only the e2e bundles its CI job has; the others point at
# a path that does not exist, so their tests skip as they do in CI, whatever an
# earlier run left under out/. $(call only,VARS) keeps VARS.
NONE := $(CURDIR)/out/.none
BUNDLE_VARS := HSLSA_BUNDLE HSLSA_BOARD_BUNDLE HSLSA_CACHE HSLSA_FPGA_OUT HSLSA_CALIPTRA_OUT
only = $(foreach v,$(BUNDLE_VARS),$(if $(filter $(v),$(1)),,$(v)=$(NONE)))

# Private keys and the simulated boards' secrets: the directories each workflow
# deletes before it uploads anything, then any key file left under out/.
KEY_DIRS := out/keys out/board-keys out/caliptra/keys out/openlane2/keys out/openlane2/rebuilder-keys \
  out/fpga/keys out/fpga/rot-keys out/fpga/rot-devices out/fpga/boards \
  $(foreach d,out/fpga/l3 out/fpga/l4,$(addprefix $(d)/,keys rot-keys buyer rot-parts rot-parts-before \
    boards received tokens softhsm2.conf verifier rebuilder lab))
CLEAN_KEYS := rm -rf $(KEY_DIRS); [[ ! -d out ]] || find out \( -name '*.key.pem' -o -name tokens -o -name softhsm2.conf \) -prune -exec rm -rf {} +
# Every e2e target deletes the keys when it ends, pass or fail.
define delete_keys_on_exit
delete_keys() { $(CLEAN_KEYS); }
trap delete_keys EXIT
endef

##@ Build

.PHONY: build dist deps tools
build: ## build the hslsa tool into bin/hslsa
	$(GO) build -o bin/hslsa ./tools/hslsa/cmd/hslsa

dist: ## static linux binaries and their licenses in dist/, what the image holds
	for arch in $(IMAGE_ARCHES); do
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags="-s -w" -o "dist/hslsa-linux-$$arch" ./tools/hslsa/cmd/hslsa
	done
	rm -rf dist/licenses
	pilot/collect-licenses.sh dist/licenses

deps: ## download and verify the Go modules
	$(GO) mod download
	$(GO) mod verify

tools: $(call own,$(SLSA_VERIFIER)) $(call own,$(OPA)) $(call own,$(CYCLONEDX)) ## download slsa-verifier, OPA and the CycloneDX CLI at the pinned versions
	@echo "slsa-verifier $(SLSA_VERIFIER)"
	echo "opa           $(OPA)"
	echo "cyclonedx     $(CYCLONEDX)"

# fetch URL SHA256: download into the target, check its sha256, make it executable.
define fetch
[[ $$(uname -s)-$$(uname -m) == Linux-x86_64 ]] || { echo "$(notdir $@): the workflows pin the linux-amd64 build; set its variable to your own binary" >&2; exit 1; }
mkdir -p "$(@D)"
curl -sSfL --retry 3 -o "$@.part" "$(1)"
echo "$(2)  $@.part" | sha256sum -c --quiet -
chmod +x "$@.part"
mv "$@.part" "$@"
endef

$(TOOLS)/slsa-verifier-$(SLSA_VERIFIER_VERSION):
	$(call fetch,https://github.com/slsa-framework/slsa-verifier/releases/download/$(SLSA_VERIFIER_VERSION)/slsa-verifier-linux-amd64,$(SLSA_VERIFIER_SHA256))

$(TOOLS)/opa-$(OPA_VERSION):
	$(call fetch,https://github.com/open-policy-agent/opa/releases/download/$(OPA_VERSION)/opa_linux_amd64_static,$(OPA_SHA256))

$(TOOLS)/cyclonedx-$(CYCLONEDX_CLI_VERSION):
	$(call fetch,https://github.com/CycloneDX/cyclonedx-cli/releases/download/$(CYCLONEDX_CLI_VERSION)/cyclonedx-linux-x64,$(CYCLONEDX_CLI_SHA256))

$(TOOLS)/ciel-$(CIEL_VERSION)/bin/ciel:
	python3 -m venv "$(TOOLS)/ciel-$(CIEL_VERSION)"
	"$(TOOLS)/ciel-$(CIEL_VERSION)/bin/pip" install -q "ciel==$(CIEL_VERSION)"

##@ Checks (CI's lint job and docs site job)

.PHONY: fmt format vet lint test vuln validate-hbom rego-test check
fmt: ## fail if a Go file needs gofmt
	@unformatted=$$(gofmt -l .)
	[[ -z $$unformatted ]] || { echo "gofmt needed: $$unformatted" >&2; exit 1; }

format: ## gofmt every Go file in place
	gofmt -l -w .

vet: ## go vet
	$(GO) vet ./...

lint: fmt vet ## gofmt and go vet

test: ## unit tests: valid records accepted, broken or forged ones refused
	$(call only) e2e/unit-tests.sh "Unit tests" -timeout $(TEST_TIMEOUT) ./...

vuln: ## known vulnerabilities in the Go toolchain and modules (govulncheck)
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

validate-hbom: ## validate the committed example HBOMs against their schema
	$(GO) run ./tools/hslsa/cmd/hslsa validate-hbom hbom/picosoc-sky130.hbom.intoto.json hbom/picosoc-devboard.hbom.intoto.json

rego-test: $(call own,$(OPA)) ## the Rego policies' tests, and OPA's strict and format checks
	$(rego_test)

define rego_test
"$(OPA)" check --strict policies/rego
"$(OPA)" fmt --fail -l policies/rego
"$(OPA)" test policies/rego hslsa.hbom_schema:hbom/hbom-predicate-v0.1.schema.json
endef

check: lint test vuln validate-hbom rego-test site ## every check above, then the docs site

##@ End-to-end examples (one target per CI job; each deletes its keys when it ends)

.PHONY: e2e e2e-chip e2e-chip-produce e2e-chip-verify e2e-escrow
e2e: e2e-chip e2e-fpga e2e-caliptra e2e-openlane ## every example: the four workflows a release runs

# hslsa-e2e.yml, job "produce": the PicoRV32 design flow and lot, the chip and
# board at L3 and L4, proxy signing, the supplier adapters, the pilot chip
# rehearsal, the simulated shuttle, HSM signing, the EDA hook, the board
# example and the escrow lot.
define chip_produce
e2e/run.sh produce
e2e/run.sh rerun
HSLSA_REQUIRE_YOSYS=1 $(call only,HSLSA_BUNDLE HSLSA_CACHE) e2e/unit-tests.sh "Design L3 and L4 tests, with Yosys" \
  -count=1 -timeout $(TEST_TIMEOUT) -run 'RerunEquivalence|DesignL4|DesignRebuild' ./tools/hslsa/
e2e/run.sh l3
e2e/board/run.sh l3
e2e/run.sh l4
e2e/board/run.sh l4
e2e/run.sh proxy
e2e/run.sh adapt
e2e/pilot/run.sh chip
e2e/run.sh shuttle
$(call only,HSLSA_BUNDLE HSLSA_CACHE) $(GO) test -count=1 -timeout $(TEST_TIMEOUT) -run 'RV32|Shuttle' ./tools/hslsa/
HSLSA_REQUIRE_PKCS11=1 $(call only,HSLSA_BUNDLE HSLSA_CACHE) $(GO) test -count=1 -timeout $(TEST_TIMEOUT) -run 'HSM|PKCS11' ./tools/hslsa/
e2e/run.sh hsm
e2e/eda-tcl/run.sh
$(call only,HSLSA_BUNDLE HSLSA_CACHE) $(GO) test -count=1 -timeout $(TEST_TIMEOUT) -run EDA ./tools/hslsa/
e2e/board/run.sh produce
e2e/board/run.sh import
e2e/escrow.sh produce
e2e/escrow.sh direct
rm -rf out/keys out/board-keys
endef

# hslsa-e2e.yml, job "verify": the buyer's checks with slsa-verifier, then the
# same bundles with OPA and openssl, the CycloneDX renderings with the official
# CLI, and the chain tests on the produced bundles.
define chip_verify
e2e/run.sh verify
e2e/board/run.sh verify
$(rego_test)
e2e/rego/run.sh --received e2e/picorv32/received-units.txt out/bundle
e2e/rego/run.sh --received e2e/board/received-boards.txt out/board
for bom in out/bundle/att/hbom.cdx.json out/board/att/hbom.cdx.json hbom/*.cdx.json; do
  echo "== $$bom"
  "$(CYCLONEDX)" validate --input-file "$$bom" --input-format json --input-version v1_6 --fail-on-errors
done
$(call only,HSLSA_BUNDLE HSLSA_BOARD_BUNDLE) e2e/unit-tests.sh "Chain tests on the produced bundles" \
  -count=1 -timeout $(TEST_TIMEOUT) ./tools/hslsa/
endef

# hslsa-e2e.yml, job "escrow": the auditor's full check of the withheld lot,
# the buyer's check of the auditor's VSAs, and what each view reveals.
define chip_escrow
e2e/escrow.sh audit
e2e/escrow.sh buyer
e2e/escrow.sh leaks > /dev/null
endef

e2e-chip: build tools ## hslsa-e2e.yml: PicoRV32 chip, board and escrow (all three jobs)
	$(delete_keys_on_exit)
	$(chip_produce)
	$(chip_verify)
	$(chip_escrow)

e2e-chip-produce: build tools ## its "produce" job: design flow, lot, L3, L4, adapters, board
	$(delete_keys_on_exit)
	$(chip_produce)

e2e-chip-verify: build tools ## its "verify" job: buyer checks, OPA, CycloneDX, chain tests
	$(delete_keys_on_exit)
	$(chip_verify)

e2e-escrow: build tools ## its "escrow" job: auditor and buyer (after e2e-chip-produce)
	$(delete_keys_on_exit)
	$(chip_escrow)

.PHONY: e2e-fpga e2e-fpga-produce e2e-fpga-verify e2e-fpga-l3

# fpga-board-e2e.yml, job "produce": the root of trust's chain, the iCE40
# design, the flash image and the board chain, the boards powered on, the
# board tests, and the after-sale records.
define fpga_produce
e2e/fpga/run.sh produce
e2e/fpga/run.sh boot
$(call only,HSLSA_FPGA_OUT) e2e/unit-tests.sh "FPGA board tests" -count=1 -timeout $(TEST_TIMEOUT) \
  -run 'FPGA|RoT|Board|ASC|UART|FlashHex|SoC|Provisioning|Released|Unreadable|HBOMLists|NoRoT' ./tools/hslsa/
e2e/fpga/run.sh aftersale
rm -rf out/fpga/keys out/fpga/rot-keys out/fpga/rot-devices out/fpga/boards
endef

# fpga-board-e2e.yml, job "verify": the buyer's check of the board chain and
# every booted board, then the pilot board rehearsal.
define fpga_verify
e2e/fpga/run.sh verify
e2e/pilot/run.sh board
endef

# fpga-board-e2e.yml, job "l3": the whole chain at Firmware and Assembly L3,
# then at L4, each followed by what it refuses.
define fpga_l3
"$(HSLSA)" pin go riscv64-unknown-elf-gcc riscv64-unknown-elf-cpp riscv64-unknown-elf-objcopy
$(call only) e2e/unit-tests.sh "Firmware L3 and L4 tests" -count=1 -timeout $(TEST_TIMEOUT) \
  -run 'TLog|Merkle|Inclusion|Consistency|FirmwareL3|ProvisioningSiteL3|FirmwareL4|ProvisioningSiteL4|ROMFrozen|RoTFirmwareRebuild' ./tools/hslsa/
e2e/fpga/run.sh l3
e2e/fpga/run.sh l4
endef

e2e-fpga: build tools ## fpga-board-e2e.yml: the FPGA board example (all three jobs)
	$(delete_keys_on_exit)
	$(fpga_produce)
	$(fpga_verify)
	$(fpga_l3)

e2e-fpga-produce: build tools ## its "produce" job: sign, program, boot, after-sale
	$(delete_keys_on_exit)
	$(fpga_produce)

e2e-fpga-verify: build tools ## its "verify" job: the buyer and the pilot rehearsal
	$(delete_keys_on_exit)
	$(fpga_verify)

e2e-fpga-l3: build tools ## its "l3" job: Firmware and Assembly at L3, then L4
	$(delete_keys_on_exit)
	$(fpga_l3)

.PHONY: e2e-caliptra e2e-caliptra-produce e2e-caliptra-verify e2e-caliptra-rtl

# caliptra-e2e.yml, job "produce": Caliptra's ROM, firmware and device model
# built at the pinned commits, and every record signed.
define caliptra_produce
e2e/caliptra/run.sh fetch
e2e/caliptra/run.sh build
e2e/caliptra/run.sh produce
rm -rf out/caliptra/keys
endef

# caliptra-e2e.yml, job "verify": the received units booted and checked, VSAs
# verified with slsa-verifier, then the tamper tests.
define caliptra_verify
e2e/caliptra/run.sh verify
$(call only,HSLSA_CALIPTRA_OUT) $(GO) test -v -count=1 -timeout $(TEST_TIMEOUT) ./tools/hslsa/
endef

e2e-caliptra: build tools ## caliptra-e2e.yml: the Caliptra example (produce, verify)
	$(delete_keys_on_exit)
	$(caliptra_produce)
	$(caliptra_verify)

e2e-caliptra-produce: build tools ## its "produce" job: build at the pinned commits, sign
	$(delete_keys_on_exit)
	$(caliptra_produce)

e2e-caliptra-verify: build tools ## its "verify" job: boot, check, tamper tests
	$(delete_keys_on_exit)
	$(caliptra_verify)

# caliptra-e2e.yml, job "verify-rtl", which CI runs only when dispatched by
# hand: the units on the Verilated RTL. Takes hours; RTL_STAGE=identity|boot,
# RTL_UNITS and RTL_THREADS pass through. Sources the job's setup script so
# the Verilator it may build is on PATH for the steps after it.
e2e-caliptra-rtl: build tools ## its "verify-rtl" job: boot on the RTL (hours; after e2e-caliptra)
	$(delete_keys_on_exit)
	source e2e/caliptra/rtl-runner-setup.sh
	e2e/caliptra/run.sh fetch
	e2e/caliptra/run.sh build-rtl
	e2e/caliptra/run.sh verify-rtl

.PHONY: e2e-openlane e2e-openlane-produce e2e-openlane-rebuild e2e-openlane-verify

OPENLANE_LOCK := openlane2/spm/flow.lock.json
# The released bundle, kept outside out/openlane2, where the rebuild runs.
OPENLANE_RELEASE := out/openlane2-release

# openlane2-flow.yml, job "flow": OpenLane 2 with a record per step, signoff
# STA from the EDA Tcl hook, and the release handed on.
define openlane_produce
openlane2/run.sh produce
openlane2/run.sh eda-sta
rm -rf out/openlane2/keys
release=$(OPENLANE_RELEASE)
rm -rf "$${release:?}"
cp -a out/openlane2/bundle "$$release"
endef

# openlane2-flow.yml, job "rebuild": a second builder with its own keys
# rebuilds the release and compares every step.
define openlane_rebuild
openlane2/run.sh rebuild $(OPENLANE_RELEASE)
rm -rf out/openlane2/keys out/openlane2/rebuilder-keys
endef

# openlane2-flow.yml, job "verify": the buyer's tapeout check, requiring the
# bit-exact rebuild, and the check of the signoff STA record.
define openlane_verify
openlane2/run.sh verify $(OPENLANE_RELEASE) out/openlane2/report
openlane2/run.sh eda-verify $(OPENLANE_RELEASE)
endef

e2e-openlane: build deps-openlane ## openlane2-flow.yml: RTL to GDS, rebuild, verify (all three jobs)
	$(delete_keys_on_exit)
	$(openlane_produce)
	$(openlane_rebuild)
	$(openlane_verify)

e2e-openlane-produce: build deps-openlane ## its "flow" job: OpenLane with a record per step
	$(delete_keys_on_exit)
	$(openlane_produce)

e2e-openlane-rebuild: build deps-openlane ## its "rebuild" job: a bit-exact rebuild by a second builder
	$(delete_keys_on_exit)
	$(openlane_rebuild)

e2e-openlane-verify: build ## its "verify" job: the buyer's tapeout check
	$(delete_keys_on_exit)
	$(openlane_verify)

##@ Docs site

.PHONY: site site-serve
site: ## build the docs website into site/public and check every link in it
	site/build.sh

site-serve: ## build the site and serve it at http://localhost:1313
	site/build.sh serve

##@ Pilot kit, container image and release (docs/release.md)

.PHONY: kit kit-dry kit-check image image-push release-dry-run release version labels

# kit-check: the kit as a recipient checks it (pilot/README.md): the public
# key, the signature on the tarball, the provenance over the binaries, and
# every file's checksum. kit_pub, when set, is the key to compare with.
define kit_check
cd "$(KIT_DIR)"
tars=(*.tar.gz)
[[ $${#tars[@]} == 1 && -f $${tars[0]} ]] || { echo "want one kit in $(KIT_DIR), found: $${tars[*]}" >&2; exit 1; }
name=$${tars[0]%.tar.gz}
[[ -z $${kit_pub:-} ]] || cmp "$$name.pub.pem" "$$kit_pub"
openssl dgst -sha256 -verify "$$name.pub.pem" -signature "$$name.tar.gz.sig" "$$name.tar.gz"
rm -rf "$${name:?}"
tar -xzf "$$name.tar.gz"
(cd "$$name" && "bin/hslsa-$$($(GO) env GOOS)-$$($(GO) env GOARCH)" kit verify --pub "../$$name.pub.pem" \
  --provenance "../$$name.provenance.json" bin/hslsa-* && sha256sum -c --quiet SHA256SUMS)
rm -rf "$${name:?}"
echo "kit $(KIT_DIR)/$$name.tar.gz checked; its key's sha256 is $$(sha256sum "$$name.pub.pem" | cut -d' ' -f1)"
endef

# The release workflow publishes only a v* tag; image-push checks the same.
define check_release_version
re='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$'
[[ $(VERSION) =~ $$re ]] || { echo "set VERSION to the release tag, such as VERSION=v0.1.0-pilot.2 (now $(VERSION))" >&2; exit 2; }
endef

kit: ## build the pilot kit into out/kit, signed with HSLSA_KIT_KEY, and check it
	: "$${HSLSA_KIT_KEY:?set HSLSA_KIT_KEY to the kit owner's key file or PKCS#11 URI}"
	kit=$(KIT_DIR)
	rm -rf "$${kit:?}"
	pilot/make-kit.sh "$$kit"
	$(kit_check)

kit-dry: build ## the release dry run's kit: a throwaway key, checked, then deleted
	keydir=$$(mktemp -d)
	trap 'rm -rf "$${keydir:?}"' EXIT
	"$(HSLSA)" keygen --out "$$keydir" kit-signer
	kit=$(KIT_DIR)
	rm -rf "$${kit:?}"
	HSLSA_KIT_KEY=$$keydir/kit-signer.key.pem pilot/make-kit.sh "$$kit"
	"$(HSLSA)" pubkey --key "$$keydir/kit-signer.key.pem" --out "$$keydir/kit-signer.pub.pem"
	kit_pub=$$keydir/kit-signer.pub.pem
	$(kit_check)

kit-check: ## check the kit in out/kit as a recipient would (KIT_PUB=<key> to compare)
	kit_pub=$(if $(KIT_PUB),$(abspath $(KIT_PUB)))
	$(kit_check)

# One image per platform with the plain docker builder (FROM scratch needs no
# emulator), labelled and tagged as the release workflow does, then run.
image: dist ## build the hslsa image per platform with its OCI labels, then run it
	$(image_labels)
	for arch in $(IMAGE_ARCHES); do
	  SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) docker build --platform "linux/$$arch" "$${labels[@]/#/--label=}" \
	    -t "$(IMAGE):$(VERSION)-linux-$$arch" .
	done
	docker run --rm --platform "linux/$(RUN_ARCH)" "$(IMAGE):$(VERSION)-linux-$(RUN_ARCH)" help
	tars=($(KIT_DIR)/*.tar.gz)
	if [[ -f $${tars[0]} ]]; then
	  name=$$(basename "$${tars[0]}" .tar.gz)
	  docker run --rm --platform "linux/$(RUN_ARCH)" --user "$$(id -u):$$(id -g)" -v "$(abspath $(KIT_DIR)):/work:ro" \
	    "$(IMAGE):$(VERSION)-linux-$(RUN_ARCH)" kit verify --pub "$$name.pub.pem" --provenance "$$name.provenance.json" "$$name.tar.gz"
	fi

# The release workflow pushes the image itself; this is for pushing by hand.
# The package is private like the repository; making it public is a separate
# switch in its settings (docs/release.md).
image-push: image ## push the image to GHCR as VERSION (a v* tag at HEAD; docker login first)
	$(check_release_version)
	[[ $$(git describe --tags --exact-match HEAD 2>/dev/null) == "$(VERSION)" && -z $$(git status --porcelain --untracked-files=no) ]] || \
	  { echo "check out the clean tag $(VERSION) first: the image must be built from it" >&2; exit 1; }
	for arch in $(IMAGE_ARCHES); do docker push "$(IMAGE):$(VERSION)-linux-$$arch"; done
	docker buildx imagetools create -t "$(IMAGE):$(VERSION)" $(foreach a,$(IMAGE_ARCHES),"$(IMAGE):$(VERSION)-linux-$(a)")
	digest=$$(docker buildx imagetools inspect "$(IMAGE):$(VERSION)" --format '{{json .Manifest}}' | jq -r .digest)
	[[ $$digest == sha256:* ]]
	mkdir -p out
	echo "$(IMAGE)@$$digest" | tee out/hslsa-image.txt

release-dry-run: kit-dry image ## the release workflow's dry run: kit and image, nothing published

# Tags origin/main, not the local checkout, as docs/release.md says. Asks
# before pushing unless YES=1.
release: ## tag origin/main as VERSION and push it, which starts the release workflow
	$(check_release_version)
	git fetch -q origin main
	if git rev-parse -q --verify "refs/tags/$(VERSION)" > /dev/null || git ls-remote --exit-code -q origin "refs/tags/$(VERSION)" > /dev/null; then
	  echo "tag $(VERSION) already exists" >&2
	  exit 1
	fi
	echo "$(VERSION) would tag origin/main: $$(git log -1 --format='%h %s' origin/main)"
	echo "The release workflow then runs every test and, if all pass, publishes the kit, the private image and the release."
	if [[ "$(YES)" != 1 ]]; then
	  read -r -p "Push the tag? [y/N] " answer
	  [[ $$answer == [yY]* ]] || exit 1
	fi
	git tag "$(VERSION)" origin/main
	git push origin "refs/tags/$(VERSION)"

version: ## print the version, commit and spec revision a release from here carries
	@echo "version     $(VERSION)"
	echo "commit      $(COMMIT)"
	echo "spec        $(SPEC), revision $(SPEC_REVISION)"
	echo "latest tag  $$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo none)"
	echo "image       $(IMAGE):$(VERSION)"

labels: ## print the OCI labels the image gets
	@$(image_labels)
	printf '%s\n' "$${labels[@]}"

##@ Setup

.PHONY: deps-ubuntu deps-rust deps-caliptra-rtl deps-openlane
deps-ubuntu: ## install the examples' packages on Ubuntu 24.04 as CI does (sudo)
	sudo apt-get update -q
	sudo apt-get install -y -q --no-install-recommends $(APT_PACKAGES)
	# Ubuntu 24.04 stops unprivileged user namespaces, which the build sandbox
	# (bubblewrap) needs; this lasts until the next reboot.
	sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

deps-rust: ## the Rust toolchain the Caliptra example builds with (rustup)
	rustup toolchain install "$(RUST_TOOLCHAIN)" --profile minimal --target riscv32imc-unknown-none-elf

deps-caliptra-rtl: ## Verilator 5.052 and the build tools for e2e-caliptra-rtl
	e2e/caliptra/rtl-runner-setup.sh

deps-openlane: $(call own,$(CIEL)) ## the pinned OpenLane image and SKY130 PDK (Docker; PDK_ROOT)
	docker pull "$$(jq -r .openlane.image $(OPENLANE_LOCK))"
	"$(CIEL)" enable --pdk-root "$(PDK_ROOT)" --pdk-family "$$(jq -r .pdk.family $(OPENLANE_LOCK))" \
	  "$$(jq -r .pdk.openPdksCommit $(OPENLANE_LOCK))"

##@ Everything

.PHONY: ci all clean clean-keys distclean help
ci: check e2e ## what CI runs: every check, then every example

all: ci release-dry-run ## everything but publishing and the hours-long RTL boot

clean-keys: ## delete every private key and board secret under out/
	$(CLEAN_KEYS)

clean: ## delete what builds and runs made: out/, dist/, bin/hslsa, the built site
	rm -rf out dist bin/hslsa site/public site/content site/resources site/.hugo_build.lock

distclean: clean ## also delete downloaded tools and caches: bin/, site/.cache, Caliptra sources
	rm -rf bin site/.cache .hslsa-cache e2e/caliptra/.src e2e/caliptra/device/target e2e/caliptra/device/target-rtl

help: ## list the targets
	@awk 'BEGIN { FS = ":.*## " } /^##@ / { printf "\n%s\n", substr($$0, 5) } /^[a-z0-9-]+:.*## / { printf "  %-21s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	echo
	echo "Variables: VERSION=$(VERSION) IMAGE=$(IMAGE) IMAGE_ARCHES=\"$(IMAGE_ARCHES)\" KIT_DIR=$(KIT_DIR)"
	echo "  PDK_ROOT=$(PDK_ROOT) TEST_TIMEOUT=$(TEST_TIMEOUT) HSLSA=$(HSLSA)"
