# Cross-Platform Ransomware Detection Campaign: A 100-Run Windows-Ubuntu Behavioral Telemetry Dataset

This repository/dataset documents a frozen 100-run cross-platform
behavioral experiment for ransomware detection on Windows and Ubuntu.

## Dataset composition

| Class | Windows | Ubuntu | Total |
|---|---:|---:|---:|
| Benign | 30 | 30 | 60 |
| Ransomware | 20 | 20 | 40 |
| **Total** | **50** | **50** | **100** |

Successful pre-experiment evidence is also retained:

- Windows benign preflight/qualification: `endurance_v28`
- Ubuntu benign preflight/qualification: `endurance_v28`
- Windows ransomware preflight: 10 families
- Ubuntu ransomware preflight: 10 families

Failed, superseded, debug and non-authoritative campaign packages are
not part of the publication dataset.

## Research design

The experiment uses OS-native telemetry adapters mapped into common
behavioral definitions:

- Windows: Sysmon + Procmon
- Ubuntu: bpftrace + auditd

The scientific observation target is approximately 60 seconds.
Natural sample exit before that boundary is retained as observed.
Samples still active at the scientific boundary are terminated using the
frozen bounded process-tree procedure. A longer watchdog exists only as
an engineering fail-safe.

Post-workload telemetry capture is bounded separately from later evidence
finalization and packaging.

The common canary corpus contains 236 files. Canary modification is
behavioral evidence but is not itself an experiment-validity gate.

## Publication layout

The large telemetry/evidence dataset should be deposited in a DOI-bearing
research-data repository. The GitHub repository should contain the
reproducibility code, manifests, documentation and compact derived results.

See:

- `docs/DATASET_README.md`
- `docs/DATA_DICTIONARY.md`
- `docs/METHODOLOGY.md`
- `docs/REPRODUCTION_GUIDE.md`
- `docs/ENVIRONMENT.md`
- `docs/PROVENANCE.md`
- `docs/ETHICS_AND_SAFETY.md`
- `RELEASE_STRUCTURE.md`

## Malware distribution

**No raw ransomware executable is distributed as part of the publication
package.**

Cryptographic identities, family assignments and experimental metadata are
retained so independently and lawfully obtained artifacts can be verified.

The published telemetry dataset can be analyzed without acquiring or
executing ransomware.

## Reproducibility

The exact frozen scripts are retained for provenance. Some preserve absolute
paths from the original laboratory host. Portability maps identify values
that another researcher must adapt rather than silently changing the scripts
that generated the experiment.

## Integrity

The final publication release will include:

- complete file manifest;
- SHA-256 checksums;
- run/package identity manifests;
- frozen sample identities;
- script-retention ledger;
- publication-readiness report.

## Author

Muhammad Rashid Mughal

Affiliation: Department of Computer Sciences & IT, Faculty of Information Technology, The University of Lahore, Sargodha Campus



## Repository and dataset

GitHub repository: to be assigned before public release.

Dataset DOI: to be assigned after repository deposition.


## Licensing

- Reproducibility/source code: **MIT License** — see `LICENSE`.
- Original research dataset and documentation: **CC BY 4.0** — see `LICENSE-DATA.md`.
- Third-party software, formats, services and other third-party materials remain
  subject to their own terms and licenses.

No raw malware executable is distributed by this release.


## Public terminology note

For publication-facing archive names, the term **preflight** is used
consistently for the successful quality-control stage performed before
official runs.

Historical internal paths are intentionally unchanged:

- Windows benign preflight maps to
  `02_WINDOWS/BENIGN/qualification/endurance_v28`
- Ubuntu benign preflight maps to
  `03_UBUNTU/BENIGN/qualification/endurance_v28`
- Ransomware preflights retain their original `preflight_runs` paths.

This terminology normalization changes only public-facing labels.
No scientific evidence, file contents, hashes, or historical provenance
were altered.
