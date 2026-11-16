# Source Authority and Repository Layout

The publication source release preserves the two frozen production trees:

- `src/benign/` — final benign campaign production package.
- `src/ransomware/` — final ransomware campaign production package.
- `src/sample_selection/` — curated final sample-selection/materialization package.

Older standalone directories such as `guest_windows`, `guest_ubuntu`,
`configs`, and `schemas` are not required publication authorities because
the final production packages contain the guest helpers and frozen runtime
logic actually used by the campaign.

The historical `_PRE_D114_BACKUP` manifest directory is deliberately
excluded. It is superseded by the current campaign manifests and final
ransomware identity authority.

No raw malware executable is distributed.
