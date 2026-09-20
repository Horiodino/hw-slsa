# S.A.F.E. report fixtures

Reports this project did not write, for [`safe_test.go`](../../safe_test.go).

From [OCP-Security-SAFE](https://github.com/opencomputeproject/OCP-Security-SAFE) at commit `1c62d652073326d28aff72debb5d257c16923725` (MIT License, Copyright (c) 2023 Open Compute Project), unchanged:

| File | Source path |
| --- | --- |
| `caliptra-fmc-2023-ncc.jws` | `Reports/CHIPS_Alliance/2023/Caliptra/OCP_SAFE_-_caliptra_-_FMC.jws` (NCC Group) |
| `ncc-group.pub.pem` | `SRP_certificates/Active/NCC_Group/ocp_safe_ncc_group_ecdsa_p521.pub` |
| `caliptra-fw-2024-ioactive.jws` | `Reports/CHIPS_Alliance/2024/Caliptra/caliptra_fw_signed_report.jws` (IOActive) |
| `ioactive.pub.pem` | `SRP_certificates/Active/IOActive/ioactive-ocp-safe-ecdsa-p521-pub.pem` |

Signed with OCP's `shortform_report-main/OcpReportLib.py` at the same commit (Python 3.12, its `requirements.txt`), with a throwaway P-384 key whose public half is `ocpreportlib-fixture.pub.pem` and kid `hslsa-fixture`, over `fixture-image.bin`:

| File | Call |
| --- | --- |
| `ocpreportlib.sfr.jws` | `sign_json_report_pem(key, "ES384", "hslsa-fixture")` |
| `ocpreportlib.sfr.cose` | `sign_corim_report_pem(key, "ES384", "hslsa-fixture")` |

The report: framework 1.1, vendor "HSLSA test vendor", product "fixture image", SHA-384 and SHA-512 of `fixture-image.bin`, provider "OcpReportLib fixture (not a real review provider)", completed 2026-10-01, scope 2, one issue at CVSS 4.3. No review took place.

In the other direction, `OcpReportLib.verify_signed_json_report` and `verify_signed_corim_report` accept reports signed by `hslsa safe sign` in both forms (checked by hand when this was written, not in CI).
