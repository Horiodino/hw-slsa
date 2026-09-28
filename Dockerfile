# The hslsa reference tool as a container image, published to GHCR by
# .github/workflows/release.yml. The image holds the static hslsa binary, its
# licenses, and the spec, pilot kit docs and pilot templates under
# /usr/share/hslsa; nothing else, not even a shell.
#
# The release workflow builds the binaries first (dist/hslsa-linux-<arch>,
# the same command as pilot/make-kit.sh) and dist/licenses
# (pilot/collect-licenses.sh), so this file only copies them in:
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t <image> .
#
# Run it on files in the current directory:
#
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" <image> verify ...
FROM scratch
ARG TARGETOS
ARG TARGETARCH
COPY dist/hslsa-${TARGETOS}-${TARGETARCH} /hslsa
COPY LICENSE LICENSE-CC-BY-4.0 NOTICE THIRD_PARTY_NOTICES.md SECURITY.md /usr/share/hslsa/
COPY dist/licenses /usr/share/hslsa/licenses
COPY spec /usr/share/hslsa/spec
COPY pilot /usr/share/hslsa/pilot
COPY e2e/pilot /usr/share/hslsa/e2e/pilot
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/hslsa"]
