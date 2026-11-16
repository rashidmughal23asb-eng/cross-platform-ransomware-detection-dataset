# Data Dictionary

This dictionary describes the logical meaning of recurrent evidence fields.
Individual package manifests remain the authoritative source for exact file
membership.

## Core identifiers

| Field | Meaning |
|---|---|
| `run_id` | Unique official/preflight run identifier |
| `attempt_id` | Attempt identifier where applicable |
| `os` / platform | Windows or Ubuntu |
| `class` | Benign or ransomware |
| `family` | Ransomware family identity where applicable |
| `scenario` | Benign workload/scenario identity where applicable |
| `split` | TRAIN, VALIDATION or TEST where applicable |
| `repetition` | Frozen repetition identity, commonly A/B |
| `sample_sha256` | Cryptographic identity of ransomware sample |
| `status` | Run/package validity result |

## Timing

| Field/concept | Meaning |
|---|---|
| sample/workload start | Recorded workload causal start |
| scientific runtime | Observed workload duration |
| observation boundary | Frozen scientific time boundary |
| termination | Natural exit or bounded observation-window termination |
| telemetry tail | Post-workload capture interval |
| capture stop | Boundary after which experimental telemetry is closed |
| finalization time | Post-capture orchestration/evidence-processing time |

## Telemetry integrity

| Field/concept | Meaning |
|---|---|
| event-loss count | Collector-reported event loss |
| telemetry ready | Collector initialization/authority proof |
| capture archive | Compressed native telemetry evidence |
| package manifest | Evidence-file identity and integrity authority |

## Canary

| Field | Meaning |
|---|---|
| corpus size | 236 files |
| modified | Existing corpus files whose content changed |
| missing | Expected corpus files no longer present |
| hash mismatch | Present file differs from frozen reference hash |
| canary impact | Behavioral observation; non-gating |

## Antivirus

Windows ransomware packages can include:

- pre-run AV state;
- exclusions required by frozen methodology;
- new detections/remediation delta;
- AV intervention classification.

Historical/cumulative Defender state must not be confused with intervention
caused by the current run.

## Common evidence files

Typical files include:

- `RUN_RESULT.json`
- `PACKAGE_MANIFEST.csv`
- `RUN_FULL_VERIFICATION.json`
- `sample_prepare_receipt.json`
- `sample_execute_receipt.json`
- telemetry/capture receipts
- canary verification evidence
- compressed telemetry archives

Names can vary between campaign components. Use the package manifest and
release manifest as authority.
