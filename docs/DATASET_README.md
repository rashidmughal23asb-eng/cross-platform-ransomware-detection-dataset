# Dataset README

## Scope

The dataset contains the accepted evidence from a frozen 100-run
cross-platform ransomware-detection experiment.

### Official population

- 30 Windows benign runs
- 30 Ubuntu benign runs
- 20 Windows ransomware runs
- 20 Ubuntu ransomware runs

Total: 100 accepted official runs.

Successful preflight/qualification evidence is retained separately and is
not counted as official campaign observations.

## Directory authorities

- `02_WINDOWS/BENIGN/official_runs`
- `03_UBUNTU/BENIGN/official_runs`
- `04_WINDOWS/RANSOMWARE/preflight_runs`
- `04_WINDOWS/RANSOMWARE/official_runs`
- `05_UBUNTU/RANSOMWARE/preflight_runs`
- `05_UBUNTU/RANSOMWARE/official_runs`

Successful benign preflights:

- `02_WINDOWS/BENIGN/qualification/endurance_v28`
- `03_UBUNTU/BENIGN/qualification/endurance_v28`

## Evidence model

Each official run is preserved as a self-contained evidence package.
Depending on OS and experiment type, packages contain combinations of:

- run result/summary;
- package manifest;
- sample/workload preparation receipt;
- execution receipt;
- telemetry-capture receipt;
- recovery/snapshot evidence;
- canary evidence;
- antivirus evidence where applicable;
- compressed native telemetry;
- package/full-verification reports.

Exact package contents are authoritative through the package manifests and
release SHA-256 inventory rather than this narrative document.

## Windows telemetry

Windows observations use Sysmon and Procmon evidence.

## Ubuntu telemetry

Ubuntu observations use bpftrace and auditd evidence.

The accepted Ubuntu ransomware packages retain event-level `bpftrace.csv`
and audit logs. A post-campaign replay-sufficiency audit established that
the 20 Ubuntu ransomware packages retain a deterministic monotonic time base
and can construct cumulative causal prefixes for seconds 1 through 10
without sample re-execution.

## Canary corpus

A common 236-file corpus is used for controlled exposure.

Canary modification is not required for a valid run. Different ransomware
families can legitimately interact with different numbers of canary files.

`0/236` therefore means only that no canary impact was observed; it does
not imply absence of ransomware behavior.

## Malware files

Raw ransomware binaries are not part of the public dataset.

Malware identity is represented using cryptographic hashes, family metadata,
frozen invocation contracts and official execution receipts.

## Intended uses

Suitable uses include:

- read-only behavioral analysis;
- Detector V2 replay;
- cross-platform telemetry research;
- early-detection experiments;
- feature extraction;
- reproducibility verification;
- ransomware/benign comparative analysis.

## Restrictions

The dataset must not be interpreted as authorization to acquire, transfer
or execute malware. Researchers recreating malware-handling stages are
responsible for their own authorization, isolation, legal compliance and
institutional ethics requirements.


