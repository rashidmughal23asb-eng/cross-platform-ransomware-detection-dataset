# Manifest Status Interpretation

## Important distinction

Some files in this directory contain `status = PENDING`.

These are **immutable pre-execution design manifests** that were frozen
before the official campaign began. Their status fields were intentionally
preserved as historical provenance rather than rewritten after execution.

They must therefore **not** be interpreted as the current campaign status.

## Final campaign state

The completed publication dataset contains:

- 30 Windows benign official runs
- 30 Ubuntu benign official runs
- 20 Windows ransomware official runs
- 20 Ubuntu ransomware official runs

Total: **100 accepted official evidence packages**.

In addition, the release contains:

- 10 Windows ransomware successful preflight packages
- 10 Ubuntu ransomware successful preflight packages

The publication outcome authorities are:

- `PUBLICATION_100_OFFICIAL_RUN_INDEX.csv`
- `PUBLICATION_20_RANSOMWARE_PREFLIGHT_INDEX.csv`
- each package's `RUN_RESULT.json`
- each package's `PACKAGE_MANIFEST.csv`
- the DOI dataset SHA-256 release manifest

## Why the original manifests were not edited

Rewriting the frozen pre-execution manifests after the campaign would alter
historical provenance.

For reproducibility, the publication therefore preserves both:

1. the exact frozen design manifests; and
2. a separate final publication outcome index.

Historical README files accompanying the frozen manifests describe the
pre-execution state at the time they were created and should be read in that
context.
