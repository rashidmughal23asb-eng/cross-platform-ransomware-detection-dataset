# Sample-selection reproduction package

This package contains the authoritative, successful sample-selection and
materialization workflow retained for publication.

## authoritative/

These are the scripts/tables forming the final reproducibility path.

## supporting_audit/

These files document successful supporting checks or recovery/provenance
steps but are not the primary workflow.

## Excluded engineering versions

`SCRIPT_RETENTION_LEDGER.csv` records every original file and explains
why it is retained or excluded. Failed, debug, intermediate and
superseded scripts are intentionally omitted from the reviewer workflow.

## Safety boundary

No ransomware executable or malware archive is distributed here.

Some retained scripts document acquisition/materialization steps needed
to reproduce the original dataset construction. Use of those workflows
requires independent authorization, an isolated malware-research
environment, applicable legal/ethical approval, and compliance with
external service terms.

The publication authors do not provide authorization to obtain or execute
malware.

## Portability

Exact original scripts are retained unchanged for provenance.
`PORTABILITY_MAP.csv` identifies host-specific paths/credential-file
locations that must be adapted by another researcher.

## Analysis reproduction

Future read-only analysis of the published dataset will not require acquiring or executing malware; the official evidence dataset supports read-only
analysis/replay.


