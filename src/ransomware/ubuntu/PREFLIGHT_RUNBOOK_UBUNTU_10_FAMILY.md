# Ubuntu 10-family ransomware PREFLIGHT - owner runbook (D-119)

**Status: PREPARED AND STATICALLY VERIFIED. NOTHING HAS BEEN EXECUTED.**
Each preflight boots the guest and executes the live sample inside it - that is the point of
the rehearsal - so **the owner runs it**, not the agent.

---

## 1. What this is

A zero-official-slot rehearsal of the **complete official Ubuntu ransomware path**, once per
qualified family (10 preflights, repetition `A`), in the campaign execution order the official
runs will use.

| | |
|---|---|
| driver | `01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\RUN_UBUNTU_10_FAMILY_PREFLIGHT.ps1` |
| controller used | the FROZEN `RANSOMWARE_Official_Run_Controller.ps1`, `RunMode=Preflight` (unmodified) |
| evidence lands in | `05_UBUNTU\RANSOMWARE\preflight_runs\<RUN_ID>_<attempt>_<stamp>\` |
| official slots consumed | **0** (the controller hard-codes 0 for every non-Official mode) |
| official runs | **STILL UNAUTHORISED** - this script never authorises them |

**What it does NOT do:** it does not touch the Windows half, the manifests, the snapshots, the
canary corpus, the timing policy, the telemetry, the family set, the hashes or the splits. It
does not write to `official_runs\` and it does not modify the frozen production scripts.

## 2. Before you start

| precondition | how it is enforced |
|---|---|
| Administrator PowerShell | the driver refuses otherwise (`ADMINISTRATOR_POWERSHELL_REQUIRED`) |
| Every input pinned by SHA-256 | controller, guest helper, bridge, native base, trace, 40-run manifest, 100-run manifest, frozen family set manifest - any drift aborts before the first boot (`PINNED_INPUT_DRIFT`) |
| Both VMs off | asserted (`UBUNTU_MUST_BE_OFF_PRE_PREFLIGHT`, `WINDOWS_MUST_BE_OFF_PRE_PREFLIGHT`) |
| Ubuntu current snapshot = V11 | asserted (`UBUNTU_CURRENT_SNAPSHOT_NOT_V11`) |
| D: free >= 6.0 GiB | asserted (`DISK_BELOW_MIN_FREE`); currently ~10.6 GiB |
| `official_runs\` empty | asserted (`OFFICIAL_RUNS_NOT_EMPTY_BEFORE_PREFLIGHT`) |

## 3. The plan (10 preflights, campaign order)

| # | family | run_id | ord | split | frozen contract | guest staging root |
|---|---|---|---|---|---|---|
| 1 | Conti | `RAN_UBU_01_A` | 21 | TEST | `--path <CANARY>` | V10 |
| 2 | Bert | `RAN_UBU_02_A` | 23 | TRAIN | `--path <CANARY>` | V11 |
| 3 | Hive | `RAN_UBU_03_A` | 25 | VALIDATION | `<CANARY>` | V10 |
| 4 | BrainCipher | `RAN_UBU_04_A` | 27 | TRAIN | `<CANARY>` | V10 |
| 5 | MarioLocker | `RAN_UBU_05_A` | 29 | VALIDATION | `<CANARY>` | V10 |
| 6 | Babuk | `RAN_UBU_06_A` | 31 | TEST | `<CANARY>` | V10 |
| 7 | INC/Lynx | `RAN_UBU_07_A` | 33 | TRAIN | `--dir <CANARY>/` | V10 |
| 8 | BlackSuit/Royal | `RAN_UBU_08_A` | 35 | TRAIN | `<CANARY> -id b57e5f0c857e807a03770feb4d3aa254` | V10 |
| 9 | Buhti | `RAN_UBU_09_A` | 37 | TRAIN | `<CANARY>` | V11 |
| 10 | Monti | `RAN_UBU_10_A` | 39 | TRAIN | `--path <CANARY>` | V11 |

The contract is never typed by the driver: the controller resolves it from the **frozen family
set manifest** (`UBUNTU_V11_FINAL_FAMILY_SET_MANIFEST.csv`, sha `574d0e23...dad3`) - the single
argv-table authority - and the driver verifies afterwards that the argv actually used equals
that contract token for token.

## 4. Run it

**Copy the path from here - do not shorten it.** The driver lives at exactly:

```
C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs\01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\RUN_UBUNTU_10_FAMILY_PREFLIGHT.ps1
```

The path contains spaces, so it must stay quoted. `-File` does not accept a `...` abbreviation -
a truncated path fails with *"The argument '...' to the -File parameter does not exist."*

```powershell
# 0. SELF-TEST: formats every line the run will print. No VM, no controller, no sample.
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs\01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\RUN_UBUNTU_10_FAMILY_PREFLIGHT.ps1" -SelfTest

# 1. print the plan, execute nothing
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs\01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\RUN_UBUNTU_10_FAMILY_PREFLIGHT.ps1" -DryRun

# 2. all ten, halting at the first failure
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs\01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\RUN_UBUNTU_10_FAMILY_PREFLIGHT.ps1"

# 3. one family only (triage)
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs\01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\RUN_UBUNTU_10_FAMILY_PREFLIGHT.ps1" -Only Conti
```

Run step 0 first: it exercises every line the series will print, so a formatting defect
cannot stop the run halfway through (this is what D-121 added after one did).

`-CampaignRoot` is not needed: it defaults to the campaign root. Budget roughly 5-8 minutes per
preflight (boot, sample preparation, 60 s bounded observation under a 90 s watchdog, 10 s telemetry
tail, canary verification, guest pack, revert).

## 5. What each preflight must produce and how it is judged

The driver verifies all of these and **halts** on the first failure:

| evidence | required content |
|---|---|
| `RUN_RESULT.json` | `status=PASS`, `run_mode=Preflight`, `official_run=false`, `official_campaign_slots_consumed=0`, `watchdog_armed=true`, `recovery_verified=true`, matching `execution_order` and `family_stratum` |
| `evidence/sample_prepare_receipt.json` | `status=PASS`, `isolation_verified=true`, **`canary_count=236`** (the FROZEN common corpus, Corpus V2) |
| `evidence/sample_execute_receipt.json` | `sample_argv` **identical** to the frozen contract with `<CANARY>` replaced by the guest canary root (`ARGV_NOT_THE_FROZEN_CONTRACT` otherwise) |
| `RUN_FULL_VERIFICATION.json` | `status=PASS`, `fail=0` (every packaged evidence file re-hashed on the host) |
| `recovery/POST_RECOVERY_VERIFICATION.json` | `status=PASS`, `ubuntu_snapshot=P5G_V11_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261112`, `network_restored=true` |
| `05_UBUNTU\RANSOMWARE\official_runs\` | **still empty** - the official slot count is re-asserted after every preflight |

## 6. Halt conditions (any one stops the series)

`PINNED_INPUT_DRIFT` - a pinned input moved - `ADMINISTRATOR_POWERSHELL_REQUIRED` -
`UBUNTU_MUST_BE_OFF_PRE_PREFLIGHT` - `UBUNTU_CURRENT_SNAPSHOT_NOT_V11` - `DISK_BELOW_MIN_FREE` -
`OFFICIAL_RUNS_NOT_EMPTY_BEFORE_PREFLIGHT` - `CONTROLLER_EXIT_<n>` - `RUN_RESULT_NOT_PASS` -
`RUN_MODE_NOT_PREFLIGHT` - `OFFICIAL_RUN_FLAG_SET` - `OFFICIAL_SLOT_CONSUMED` -
`EXECUTION_ORDER_MISMATCH` - `FAMILY_MISMATCH` - `WATCHDOG_NOT_ARMED` - `RECOVERY_NOT_VERIFIED` -
`ARGV_NOT_THE_FROZEN_CONTRACT` - `SAMPLE_PREPARE_NOT_PASS` - `GUEST_ISOLATION_NOT_VERIFIED` -
`CANARY_COUNT_NOT_25` - `PACKAGE_SELF_VERIFICATION_NOT_PASS` - `RECOVERY_NOT_PASS` -
`RECOVERY_SNAPSHOT_NOT_V11` - `HOST_NETWORK_NOT_RESTORED` - `OFFICIAL_RUNS_DIR_NOT_EMPTY`.

On a halt the failing family's evidence package is preserved, the remaining families are **not**
attempted, and the summary records the reason.

## 7. The summary receipt

`05_UBUNTU\RANSOMWARE\preflight_runs\PREFLIGHT_SUMMARY_<stamp>.json` records, per family: the
exit code, the evidence package path, the argv actually used, the termination mode, whether the
watchdog fired, whether the recovery was verified, and the guest snapshot - plus
`official_campaign_slots_consumed: 0` and `official_runs_authorised: false`.

## 8. The gate that stays closed

**The official Ubuntu ransomware runs remain UNAUTHORISED.** They may only be authorised by the
owner, and only after **all ten preflights have passed**. A preflight PASS proves the *path*
(baseline, isolation, staging, frozen contract, telemetry, watchdog, canary, pack, revert); it is
not itself an official run and it does not consume a campaign slot.
