# Reproduction Guide

Two distinct forms of reproducibility are supported.

## A. Analysis reproduction — recommended

This path does **not** require obtaining or executing malware.

1. Obtain the published evidence dataset from the DOI-bearing data repository.
2. Verify the release SHA-256 manifest.
3. Obtain the GitHub reproducibility repository.
4. Verify script/repository checksums.
5. Read the frozen methodology and data dictionary.
6. Parse accepted official packages only.
7. Normalize native Windows and Ubuntu evidence using the frozen analysis
   implementation.
8. Reconstruct the frozen causal checkpoints.
9. When the final Detector V2 analysis implementation is frozen, use it to reproduce feature extraction, scoring, and thesis analyses.
10. Record software/environment versions and derived-output hashes.

This is the intended reviewer path.

## B. Dataset-construction reproduction — controlled malware laboratory

The publication also preserves the frozen sample-selection/materialization
logic for methodological transparency.

This path can involve malware handling and therefore requires:

- explicit authorization;
- an isolated malware-analysis environment;
- applicable institutional/ethics approval;
- independent legal review where required;
- compliance with external source/service terms;
- researcher-supplied credentials;
- independent verification of all published SHA-256 identities.

No public dataset/repository release should be interpreted as permission to
obtain or execute malware.

## Frozen scripts

The publication preserves exact scripts rather than silently modifying their
historical paths.

Portability maps document host-specific values another laboratory must adapt.

## Do not change

A strict reproduction should not post-hoc alter:

- family/split assignments;
- frozen sample hashes;
- repetitions;
- observation timing;
- canary corpus identity;
- AV policy;
- telemetry collector semantics;
- accepted evidence gates.

Changes to these define a new experiment rather than a reproduction.


