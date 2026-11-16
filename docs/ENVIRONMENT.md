# Experimental Environment

This document reports only environment facts supported by retained campaign
evidence. Versions that were not recorded reliably during the campaign are
not reconstructed retrospectively.

## Operating systems

### Windows guest

Accepted official and preflight recovery evidence identifies the Windows
research guest as:

**Windows 11**

This identification is repeated across accepted Windows evidence packages.

### Ubuntu guest

The frozen orchestration/scripts consistently identify the Ubuntu VM through
the laboratory VM path/name:

`D:\Ubuntu 24.04\Ubuntu.vmx`

This supports the original laboratory designation **Ubuntu 24.04**.

However, the publication archive does not currently contain a sufficiently
strong retained guest OS-version receipt (for example, a frozen
`/etc/os-release` record) from which an exact Ubuntu release/build can be
independently re-derived. Therefore the VM designation is reported as
provenance rather than as a stronger claim about an exact guest build.

## Host scripting/runtime

Retained production and audit scripts explicitly reference:

**Windows PowerShell 5.1**

A retained qualification receipt also records:

- host Python 3.12
- capstone 5.0.7

The publication does not infer a more specific Python 3.12 patch version
from this receipt.

## Native telemetry collectors

The frozen methodology and production scripts establish the collector roles:

### Windows

- Sysmon
- Procmon

### Ubuntu

- bpftrace
- auditd

The exact installed versions of Sysmon, Procmon, bpftrace and auditd were
not recoverable from retained authoritative campaign evidence.

These versions are therefore reported as:

**NOT RECORDED / NOT RECOVERABLE FROM THE RETAINED PUBLICATION EVIDENCE**

No version numbers have been guessed from current software releases,
filenames, or the present host environment.

## Virtualization

The campaign used VMware Workstation/native VIX orchestration.

The retained publication evidence does not establish a sufficiently strong
exact VMware Workstation version receipt. Accordingly, no exact VMware
version is claimed.

## Detector development context

The retained orchestration contains references to the historical
Detector V2 / Alpha.11 development and qualification workflow.

The 100-run campaign evidence is being published independently from the
subsequent final Detector V2 thesis-analysis stage. Publication of this
dataset therefore does not imply that the final Detector V2 analysis has
already been completed.

## Reproducibility implication

Analysis reproducibility depends primarily on:

- immutable retained evidence;
- run/package manifests;
- native telemetry semantics;
- frozen normalization/analysis implementation used by the researcher;
- documented timing, scoping and causal rules.

Where an exact software version was not recorded, this limitation is stated
rather than silently reconstructed after the experiment.

See `audits/environment/ENVIRONMENT_VERSION_EVIDENCE.csv` in the final publication package for
the underlying retained-evidence audit.

