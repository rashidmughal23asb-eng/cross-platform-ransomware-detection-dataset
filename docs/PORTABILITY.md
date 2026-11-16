# Portability

The exact frozen scripts are intentionally preserved unchanged because they
are provenance authorities for the completed campaign.

Absolute paths therefore remain visible in some scripts.

Use `PORTABILITY_MAP_ALL.csv` to distinguish:

- `HOST_USER_PATH` — workstation-specific and should be adapted.
- `VM_STORAGE_PATH` — local VMware storage path and should be adapted.
- `FROZEN_GUEST_LAB_PATH` — experiment guest path; preserve it for strict
  reconstruction unless intentionally defining a new experimental protocol.

The publication does not silently rewrite the scripts that produced the
accepted evidence.
