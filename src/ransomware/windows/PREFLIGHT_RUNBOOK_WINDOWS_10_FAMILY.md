# Windows 10-family ransomware PREFLIGHT - owner runbook (D-132)

**Status: PREPARED AND STATICALLY VERIFIED (17/17). NOTHING HAS BEEN EXECUTED.**
Each preflight boots the Windows guest and executes the live sample inside it - that is the point
of the rehearsal - so **the owner runs it**.

---

## 1. What this is

One rehearsal of the complete official **Windows** ransomware path per qualified family
(10 families, repetition A), executed **one at a time, sequentially**, in campaign execution
order (1, 3, 5 … 19), through the **frozen** Windows controller
(`RANSOMWARE_Official_Run_Controller.ps1`, `RunMode=Preflight`). Each run is a separate, complete
cycle:

```
boot the Windows guest from the frozen R5 baseline
  -> stage the sample read-only + the FROZEN 236-file canary corpus
  -> Sysmon + Procmon telemetry (bpftrace/auditd are the Ubuntu adapter)
  -> execute the sample under the 60 s bounded observation, 90 s watchdog
  -> canary integrity re-hash
  -> evidence pack (zip) -> power off -> revert to the R5 Windows baseline
  -> restore the host network and the VMware GUI entries
```

It consumes **0 of the 40 official campaign slots** and writes to
`04_WINDOWS\RANSOMWARE\preflight_runs\`.

| # | family | run_id | ord | split | fixture seed |
|---|---|---|---|---|---|
| 1 | Carso | `RAN_WIN_01_A` | 1 | TRAIN | R01-WIN-A |
| 2 | RustyStealer | `RAN_WIN_02_A` | 3 | TEST | R02-WIN-A |
| 3 | Embargo | `RAN_WIN_03_A` | 5 | TRAIN | R03-WIN-A |
| 4 | GreenBlood | `RAN_WIN_04_A` | 7 | TRAIN | R04-WIN-A |
| 5 | OpnKey | `RAN_WIN_05_A` | 9 | VALIDATION | R05-WIN-A |
| 6 | Akira | `RAN_WIN_06_A` | 11 | TRAIN | R06-WIN-A |
| 7 | WannaCry | `RAN_WIN_07_A` | 13 | TEST | R07-WIN-A |
| 8 | Adware.Yogi | `RAN_WIN_08_A` | 15 | TRAIN | R08-WIN-A |
| 9 | ClearWater | `RAN_WIN_09_A` | 17 | TRAIN | R09-WIN-A |
| 10 | LCRYX | `RAN_WIN_10_A` | 19 | VALIDATION | R10-WIN-A |

## 2. Before you start

| precondition | enforced by |
|---|---|
| Administrator PowerShell | the driver (`ADMINISTRATOR_POWERSHELL_REQUIRED`) |
| every input pinned by SHA-256 | the driver (`PINNED_INPUT_DRIFT`) |
| both VMs off; the Windows guest on R5; the Ubuntu guest on V11 | the driver |
| D: free >= 6.0 GiB | the driver |
| no Windows preflight and no Windows official run yet | the driver |

## 3. Run it

```powershell
# 0. self-check: every printed line formats, nothing is executed
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs\01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RUN_WINDOWS_10_FAMILY_PREFLIGHT.ps1" -DryRun

# 1. all ten, halting at the first failure
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs\01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RUN_WINDOWS_10_FAMILY_PREFLIGHT.ps1"
```

Budget roughly 4-7 minutes per family.

## 4. Two Windows-specific facts you must know

**(a) No Windows invocation contract is frozen.** The ten Windows families were **never
qualified** (the qualification campaign was Ubuntu-only), their binaries are **guest-only** (no
host copy exists to mine for usage evidence), and the frozen Windows controller launches the
sample with **NO ARGUMENTS**. The driver records `argv_actually_used = NO_ARGUMENTS` on every run
and the summary states the contract status explicitly. Nothing was invented here.

*Consequence:* a family whose behaviour is to encrypt broadly may damage the guest's own evidence
area (the canary corpus sits beside the receipts). That is contained - the guest is reverted - and
**a failed run is itself the finding**: that family needs a path contract before its official runs.
The per-family canary result (modified vs 236) is the evidence for the decision.

**(b) The canary corpus is now the FROZEN common corpus.** The Windows executor carried the same
25-file placeholder the Ubuntu one had (`canary_NNN.dat`, 16 KiB, no extensions). It now stages the
**same frozen 236-file corpus** as the Ubuntu half (one file per documented target extension,
256 KiB / 1 MiB / 4 MiB cycle, every fifth file nested, read-only) - proved to be identical to the
frozen artefact (236 files, 47 nested, 430,702,592 bytes, the same per-file hashes). The Windows
manifest **format** is unchanged, so the frozen canary verifier is untouched.

## 5. What each preflight must produce and how it is judged

| evidence | required content |
|---|---|
| `RUN_RESULT.json` | `status=PASS`, `run_mode=Preflight`, `official_run=false`, `official_campaign_slots_consumed=0`, `watchdog_armed=true`, `recovery_verified=true` |
| `evidence\sample_prepare_receipt.json` | `status=PASS`, `isolation_verified=true`, **`canary_count=236`** |
| `evidence\sample_execute_receipt.json` | the watchdog arming, the exit code, the termination mode and the actual duration |
| `evidence\canary_integrity_receipt.json` | `total=236`, the mismatches (the canary modification count) |
| `evidence\telemetry_capture_receipt.json` | the Sysmon+Procmon capture (the detector's input) |
| `recovery\POST_RECOVERY_VERIFICATION.json` | `status=PASS`, the Windows snapshot back on R5, the host network restored |
| `capture_archive.zip` + `RUN_FULL_VERIFICATION.json` | the archive present and the package self-verification `PASS` with `fail=0` |

## 6. Halt conditions

`ADMINISTRATOR_POWERSHELL_REQUIRED` · `PINNED_INPUT_DRIFT` · `WINDOWS_MUST_BE_OFF_PRE_PREFLIGHT` ·
`UBUNTU_MUST_BE_OFF_PRE_PREFLIGHT` · `WINDOWS_CURRENT_SNAPSHOT_MISMATCH` ·
`UBUNTU_CURRENT_SNAPSHOT_MISMATCH` · `DISK_BELOW_MIN_FREE` · `WINDOWS_PREFLIGHT_RUNS_NOT_EMPTY` ·
`WINDOWS_OFFICIAL_RUNS_NOT_EMPTY_AT_START` · `CONTROLLER_EXIT_<n>` · `RUN_RESULT_NOT_PASS` ·
`RUN_MODE_NOT_PREFLIGHT` · `OFFICIAL_RUN_FLAG_SET` · `SLOT_COUNT_NOT_ZERO` · `WATCHDOG_NOT_ARMED` ·
`RECOVERY_NOT_VERIFIED` · `SAMPLE_PREPARE_NOT_PASS` · `GUEST_ISOLATION_NOT_VERIFIED` ·
`CANARY_COUNT_NOT_236` · `RECOVERY_NOT_PASS` · `RECOVERY_WINDOWS_SNAPSHOT_NOT_R5` ·
`HOST_NETWORK_NOT_RESTORED` · `CAPTURE_ARCHIVE_MISSING` · `PACKAGE_SELF_VERIFICATION_MISSING` ·
`PACKAGE_SELF_VERIFICATION_NOT_PASS` · `PREFLIGHT_PACKAGE_COUNT_NOT_PLUS_ONE`.

On a halt the failing family's evidence package is kept, no further family is attempted, and
**0 slots** are consumed. The summary is written to
`01_SHARED\audit\WINDOWS_10_FAMILY_PREFLIGHT_20261112\` - deliberately **not** into
`04_WINDOWS\RANSOMWARE\results\`, which the D-040 policy reserves for the final official results
manifest.

## 7. The gate that stays closed

**The official Windows ransomware runs remain NOT authorised.** They may only be authorised by the
owner after this preflight passes - and, given (a) above, the decision on the Windows invocation
contracts is part of that authorisation.
