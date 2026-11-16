# Frozen Methodology

## Experimental unit

An official run is an independent frozen campaign observation with a
run identifier, OS/class assignment, workload/sample identity, telemetry,
evidence package and recovery verification.

## Platform design

Windows and Ubuntu use native telemetry collectors rather than forcing one
collector stack across both operating systems.

The platform-specific telemetry is intended to be mapped into common
behavioral definitions for downstream Detector V2 analysis.

## Observation timing

Frozen timing principles:

1. Scientific target: approximately 60 seconds.
2. Natural exit earlier than the target is accepted and recorded.
3. A sample still active at the scientific boundary is terminated using the
   frozen complete-tree teardown procedure.
4. The 90-second watchdog is an engineering emergency boundary, not an
   extension of the scientific observation window.
5. A bounded post-workload telemetry tail is retained.
6. Evidence finalization, hashing, packing and transfer occur after capture
   and must not be interpreted as additional behavioral observation time.

## Isolation and recovery

Runs use isolated virtual machines and frozen snapshot baselines.

Recovery is part of experiment validity. Accepted evidence must demonstrate
the required baseline restoration and campaign isolation state.

## Antivirus policy

Windows ransomware observations retain the frozen Defender policy rather
than globally disabling real-time protection.

AV intervention is recorded explicitly and is not silently ignored.

## Canary policy

The common Corpus V2 contains 236 files.

Canary behavior is non-gating:

- explicit sample targeting can produce substantial modification;
- generic traversal can produce partial modification;
- no canary interaction can also be legitimate.

Fairness requires equivalent exposure opportunity, not identical modification
counts across ransomware families or operating systems.

## Leakage control

Train/validation/test allocation is frozen before final analysis.

Ransomware repetitions remain within their family/split allocation to avoid
family leakage.

No family is selected or rejected because it produces a desired Detector V2
score.

## Evidence-first policy

The experiment is fail-closed. A run is accepted only when its required
scientific and evidence-integrity gates pass.

Failed/superseded engineering attempts are excluded from the publication
dataset rather than mixed with successful observations.
