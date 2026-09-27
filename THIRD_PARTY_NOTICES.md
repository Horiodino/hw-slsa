# Third-party files

These files are not under this repository's [LICENSE](LICENSE). Each stays under its own license, as listed. The `hslsa` binaries in a pilot kit also contain Go modules under their own licenses; the kit's `licenses/` directory carries each module's license text.

| Files | From | License | Changed |
| --- | --- | --- | --- |
| `openlane2/overlay/scripts/klayout/stream_out.py`, `openlane2/overlay/scripts/magic/def/mag_gds.tcl`, `openlane2/overlay/scripts/openroad/common/io.tcl` | [OpenLane 2](https://github.com/efabless/openlane2) 2.3.10, `openlane/scripts/`, Copyright Efabless Corporation | Apache License 2.0 | Yes: each file says what changed, and [openlane2/overlay/README.md](openlane2/overlay/README.md) explains why |
| `hbom/formats/cyclonedx-1.6/*.schema.json` | [CycloneDX specification](https://github.com/CycloneDX/specification) tag 1.6.1, Copyright OWASP Foundation | Apache License 2.0 | No |
| `hbom/formats/spdx-3.1-rc1/schema.json` | [SPDX specification](https://spdx.github.io/spdx-spec/3.1-RC1/) 3.1-RC1, Copyright the Linux Foundation and SPDX contributors | Community Specification License 1.0 | No |
| `tools/hslsa/testdata/safe/caliptra-fmc-2023-ncc.jws`, `caliptra-fw-2024-ioactive.jws`, `ncc-group.pub.pem`, `ioactive.pub.pem` | [OCP-Security-SAFE](https://github.com/opencomputeproject/OCP-Security-SAFE) commit `1c62d652073326d28aff72debb5d257c16923725`, Copyright (c) 2023 Open Compute Project | MIT License (below) | No |
| `e2e/caliptra/device/` | Written for this repository against [caliptra-sw](https://github.com/chipsalliance/caliptra-sw), whose crates it links | Apache License 2.0, as its files and `Cargo.toml` state | Not a copy |

The Apache License 2.0 is at https://www.apache.org/licenses/LICENSE-2.0 and the Community Specification License 1.0 at https://github.com/CommunitySpecification/1.0.

## MIT License (OCP-Security-SAFE)

```
Copyright (c) 2023 Open Compute Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
