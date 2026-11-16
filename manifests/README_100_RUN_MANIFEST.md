# 100-run campaign manifest (ransomware phase)

Target fixed by `DECISIONS.md` D-036: **100 official runs** = 60 benign (complete, all PASS)
+ 40 ransomware (pending, 0 official slots consumed). These files are host-only artefacts:
generating and re-pointing them touched no VM, no sample and no evidence file.

**This file is documentation only.** It was reconciled against the authoritative manifests on
2026-11-12 (D-118): every SHA-256 below is the live hash of the file on disk, the encoding
statement is the per-file reality, and the split and baseline sections describe the frozen
state instead of the proposal this file originally carried. **No manifest, no hash inside a
manifest, no split, no snapshot, no case package and no runner was changed by that
reconciliation.**

## Files

| file | rows | encoding | purpose | SHA-256 |
| --- | --- | --- | --- | --- |
| `BENIGN_60_RUN_MANIFEST.csv` | 60 | UTF-8 **with BOM** | the benign authority - the source of the 60 benign rows | `41a2ec93552cd2a29c54a7fa2c8abd9c4489ae6f509ec330005a26751023bf0f` |
| `BENIGN_60_RUN_MANIFEST.json` | - | UTF-8 no BOM | the benign manifest in JSON form | `7898f0880f8b781416885ac07bb3f741d9439af4f0c4e36ab5897e1d3bb92263` |
| `BENIGN_60_RUN_SCENARIO_MATRIX.csv` | 15 | UTF-8 no BOM | the benign scenario matrix (15 scenarios) | `1433cf0527d14ce6c945433df4501845b49848db770491f178d421b3a3eec402` |
| `CAMPAIGN_100_RUN_MANIFEST.csv` | 100 | UTF-8 **no BOM** | the single campaign ledger: the 60 benign rows followed by the 40 ransomware rows | `db9dd99fbeaccc24a41fed47a0f933ae14ed2cd5c42b42f0b72a9232d2d9ef53` |
| `RANSOMWARE_40_RUN_MANIFEST.csv` | 40 | UTF-8 no BOM | authoritative sample identity and per-run facts for the ransomware block | `3f1065c7030b36e86f9f5cf9fa6de8bf533d3b9b4fb96307e02b29f4e563a6e6` |
| `RANSOMWARE_40_RUN_MANIFEST_META.json` | - | UTF-8 no BOM | sources, split rule, replacements, guest verification, pending items | `2a41bb053cdd5dbfe780f27ad949b425e05a6dbdfaec552ae81b5a7acbcec371` |

**Encoding.** Only `BENIGN_60_RUN_MANIFEST.csv` carries a UTF-8 BOM. The campaign manifest and
the ransomware manifest are UTF-8 **without** a BOM, so a byte comparison of the three CSVs
differs in the first three bytes. This README is itself UTF-8 without BOM, LF line endings.

(The earlier claim "Both CSVs are UTF-8 with BOM" was wrong and has been removed.)

## Schema

`RANSOMWARE_40_RUN_MANIFEST.csv` (18 columns) carries the sample facts that the 17-column
campaign schema cannot hold:

```
run_id, execution_order, platform, sample_run_id, family_stratum, sample_sha256, sample_bytes,
sample_guest_path, read_only, mode_octal, repetition, split, ground_truth, snapshot_baseline,
telemetry_adapter, expected_duration_seconds, source_manifest_sha256, status
```

`CAMPAIGN_100_RUN_MANIFEST.csv` reuses the benign 17-column schema exactly, so the 60 benign
rows are carried over **value-for-value**: the generator asserts every field of every row
against `BENIGN_60_RUN_MANIFEST.csv` and refuses on any drift (`BENIGN_ROW_DRIFT`). The
ransomware rows map into the same columns:

| campaign column | ransomware value |
| --- | --- |
| `run_id` | `RAN_WIN_01_A` ... `RAN_UBU_10_B` |
| `scenario_id` | sample id, `W-R-01` / `L-R-01` |
| `scenario_name` | family, sanitised upper case (`CONTI`, `BLACKSUIT_ROYAL`) |
| `scientific_supergroup` | `RANSOMWARE` |
| `scenario_run_id` | `W-R-01-A`, `L-R-01-B`, ... |
| `lead_application` | family stratum (`Carso`, `Bert`, ...) |
| `process_density_role` | `MALICIOUS_PRIMARY_SUBJECT` (benign rows: `DIAGNOSTIC_NOT_PRIMARY_PREDICTOR`) |
| `expected_duration_seconds` | `60` - frozen by the runner (D-114/D-115) |
| `status` | `PENDING` for all 40 rows until the run executes |

`run_id` is the join key between the two files. Nothing else is duplicated.

## Repetitions and ordering

Each of the 20 samples runs twice - repetitions `A` then `B`, adjacent in `execution_order`
(1-40), Windows block first, then Ubuntu. `RAN_WIN_01_A` and `RAN_WIN_01_B` are distinct rows
and must never be deduplicated: they measure within-sample variance of the same frozen binary.

## Sample facts and their sources

Every sample fact (`sample_sha256`, `sample_bytes`, `sample_guest_path`, `mode_octal`) is
carried in the manifest and re-checked when the sample was verified in the guest.

- **Windows rows** carry `source_manifest_sha256 = 9e935ef47f914c4cfa9bcd65bcd47ac479ce9138a29b2ead66be61e07ab22f94`
  - the live `P5G_R4_R4` Windows materialization manifest, kept outside this folder at
  `C:\Ransomware_Thesis_CrossOS_2026\10_DETECTOR_FREEZE\P5G_R4_R4_GUEST_ONLY_EXACT_SAMPLE_MATERIALIZATION\P5G_R4_R4_PASS\P5G_R4_R4_WINDOWS_MATERIALIZATION_MANIFEST.csv`.
- **Ubuntu rows** carry `source_manifest_sha256 = 6b0a3f149a4627b46a9fad3a443dfbb29ec0fc49552cde68a2a1228739a67dc9`.
  This is a **historical pointer** to the campaign manifest as it stood when the Ubuntu rows
  were re-pointed (before the D-117 benign-row restoration), not a claim that the campaign
  manifest still hashes to that value. The live campaign-manifest hash is
  `db9dd99fbeaccc24a41fed47a0f933ae14ed2cd5c42b42f0b72a9232d2d9ef53`; D-117 changed only the `snapshot_baseline`
  field of the 30 benign rows, so **no ransomware row's content changed**.
- **Windows staging paths**: all 20 Windows rows stage from
  `C:\RansomLab\MalwareStaging\P5G\R4\Samples\<sha256>.sample` with `read_only = True`;
  `mode_octal` is empty for the Windows rows, because a POSIX mode does not apply there.
- **Ubuntu staging paths**: 14 rows at `/opt/RansomLab/MalwareStaging/P5G/V10/Samples`
  and 6 rows at `/opt/RansomLab/MalwareStaging/P5G/V11/Samples` (Bert, Buhti, Monti);
  every one of the 20 Ubuntu rows carries `read_only = true` and `mode_octal = 000`.
- The ten qualified Ubuntu families were verified **inside the guest** on 2026-11-12
  (10/10 exact SHA-256, byte count, owner root:root, mode 000) before the offline V11
  snapshot was created: `ransomware_executed = false`, `official_slots_consumed = 0`.

## Split rule - FROZEN

```
status: FROZEN (operator-confirmed 2026-11-12, D-114 Option A)
granularity: family
families: 12 TRAIN / 4 VALIDATION / 4 TEST   (20 distinct families, 10 per OS)
runs:     24 TRAIN / 8 VALIDATION / 8 TEST    (60 / 20 / 20 percent of 40)
per OS:    6 TRAIN / 2 VALIDATION / 2 TEST families  =  12 / 4 / 4 runs
```

- No family appears in more than one split, and **no family is shared between the two
  operating-system sets** - the Windows set is Carso, RustyStealer, Embargo, GreenBlood,
  OpnKey, Akira, WannaCry, Adware.Yogi, ClearWater, LCRYX, and the Ubuntu set is exactly the
  ten qualified families (Conti, Bert, Hive, BrainCipher, MarioLocker, Babuk, INC/Lynx,
  BlackSuit/Royal, Buhti, Monti).
- `Akira` is now Windows-only (`W-R-06`). Its former Ubuntu slot was re-pointed twice:
  `L-R-08` Akira -> BlackBasta -> BlackSuit/Royal, and `L-R-01` Qilin/Agenda -> Gunra -> Conti
  (D-044, then D-114). The run counts, the 12/12 OS balance and the zero-family-leakage
  structure are unchanged by those replacements.
- The split stays family-level by rule: both repetitions of a sample and both OS copies of a
  family would otherwise risk landing in different splits.

**Regeneration caution.** The generator `01_SHARED\scripts\host\BUILD_100_RUN_MANIFEST.ps1`
still carries its pre-D-114 default parameters (`-TrainFamilies 11 -ValidationFamilies 4`).
Those defaults describe the *historical* configuration and do **not** reproduce the current
frozen files, because the 20 Ubuntu rows were re-pointed afterwards by
`APPLY_UBUNTU_SAMPLE_REPLACEMENT.ps1` (D-044, then D-114). Re-running the generator is
therefore not a documentation-neutral operation and must not be used to "refresh" these files.

## Baseline distinction - the benign half on R5, the ransomware half on V11

| rows | count | `snapshot_baseline` | why |
| --- | --- | --- | --- |
| benign Windows | 30 | `P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013` | the baseline the 30 collected benign Windows runs were executed on |
| benign Ubuntu | 30 | `P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013` | the baseline the 30 collected benign Ubuntu runs were executed on |
| ransomware Windows | 20 | `P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013` | unchanged - the Windows half was never re-baselined |
| ransomware Ubuntu | 20 | `P5G_V11_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261112` | the ten qualified families are materialised there |

- The two halves run on **different Ubuntu snapshots by construction**: the benign half on
  **R5**, the ransomware half on **V11**.
- V11 is a direct child of V10, which is a direct child of R5, on one vmdk chain, so both
  halves share one guest disk image. The only content difference is **22 inert sample files**
  (19 at the V10 staging root, 3 at the V11 root; files mode `000` root:root, directories
  `700` root:root) plus the volatile state of the boots that performed the materialisation.
  No package, service, user, kernel or configuration change occurred.
- R5 was **already** a post-materialisation snapshot: it carried 10 frozen samples at the R4
  staging root, and that root is preserved 10/10 in V10 and in V11.
- The difference is a **snapshot-identity difference only**, and it is methodologically
  equivalent for the detector experiment: the telemetry instrument is byte-identical in both
  halves, the observation timing is identical (pre-roll 5 s, active window 60 s, post-tail
  10 s), the network isolation posture is equivalent in effect, the VMX hardening gate and
  the bridge/recovery path are identical, and the detector is an external offline component
  whose canonical Linux source is the bpftrace rows - so the baseline identity never reaches
  the feature pipeline. Audit receipt:
  `01_SHARED\audit\BASELINE_EQUIVALENCE_R5_V11_20261112\BASELINE_EQUIVALENCE_AUDIT_REPORT.md`
  (sha `f067800f9bccd6682e8bd8afefbaa8a1a0bc6e3b5f7f397d20245ff9e62a28c8`), 39/39 checks PASS; the JSON
  receipt beside it embeds the run timestamp, so its own hash changes on every re-verification - the
  report hash above is the stable one.
- **Provenance rule.** The 30 collected benign Ubuntu runs were collected under R5 and each
  records that baseline in its own `POST_RECOVERY_VERIFICATION.json`; their run packages are
  never rewritten. The 60 benign rows of the campaign manifest are carried over value-for-value
  from `BENIGN_60_RUN_MANIFEST.csv` (generator assertion `BENIGN_ROW_DRIFT`), and after the
  D-117 correction the drift is 0.

## Frozen invocation contracts (Ubuntu)

The official Ubuntu runner launches each family with the exact contract under which that
family was qualified. The per-family argv table **is** the frozen family set manifest
`01_SHARED\sample_selection\UBUNTU_V11_FINAL_FAMILY_SET_20261112\UBUNTU_V11_FINAL_FAMILY_SET_MANIFEST.csv`
(sha `574d0e237e57b9bfc58918dacd61020ddb0244975e5190ecdbdef4e077c3dad3`) - the single
authority; no second copy of the contracts exists.

| family | frozen contract |
| --- | --- |
| INC/Lynx | `--dir <CANARY>/` |
| Conti | `--path <CANARY>` |
| Babuk | `<CANARY>` |
| Hive | `<CANARY>` |
| MarioLocker | `<CANARY>` |
| BrainCipher | `<CANARY>` |
| BlackSuit/Royal | `<CANARY> -id b57e5f0c857e807a03770feb4d3aa254` |
| Bert | `--path <CANARY>` |
| Buhti | `<CANARY>` |
| Monti | `--path <CANARY>` |

`<CANARY>` is substituted with the guest canary root at run time. The controller fails closed
on an unknown family, an empty contract or a hash mismatch; the guest helper fails closed on an
argv count mismatch; the sample's argv[0] remains the staged sample path. Static verification:
`01_SHARED\scripts\host\qualification\VERIFY_UBUNTU_OFFICIAL_RUNNER_CONTRACTS.py`
(sha `90bb91a7f7b0fa9456250d14c7a36c416d13252571214f6933eca82eb4905a6a`) - PASS, 0 failures.

## Gate

The three D-036 preconditions are now met:

1. the split rule was confirmed by the operator and recorded as a dated decision
   (D-114, Option A, 2026-11-12; `RANSOMWARE_40_RUN_MANIFEST_META.json` records
   `confirmed_by` and `confirmed_utc`),
2. `expected_duration_seconds` is frozen at **60** in every row of both manifests,
3. the manifests are hashed and frozen
   (`RANSOMWARE_40_RUN_MANIFEST_META.json` carries `schema_version = 1.0-frozen`).

What remains is a **separate, explicit authorisation**: the official runs have not been
authorised and none has been executed. All 40 ransomware rows still carry `status = PENDING`
and the block has consumed **0 official campaign slots**. The qualification ledger records 10
qualified distinct Ubuntu families, 0 provisional contracts and
`final_family_set_freeze_eligible = true`.

## Reconciliation log (documentation only - D-118)

| what | before this edit | now |
| --- | --- | --- |
| `RANSOMWARE_40_RUN_MANIFEST.csv` hash | `211966fa4a9dbf32013dd1415254f75e0c425194b9a9576ac1abb5e2d79f81da` (pre-D-044/D-114) | `3f1065c7030b36e86f9f5cf9fa6de8bf533d3b9b4fb96307e02b29f4e563a6e6` |
| `CAMPAIGN_100_RUN_MANIFEST.csv` hash | `081f472ef334f648d3373687c4b377b0c4f4e0d54c87aab21ecc9482dbd62c7d` (pre-D-044/D-114) | `db9dd99fbeaccc24a41fed47a0f933ae14ed2cd5c42b42f0b72a9232d2d9ef53` (post-D-117) |
| `RANSOMWARE_40_RUN_MANIFEST_META.json` hash | not listed ("generated") | `2a41bb053cdd5dbfe780f27ad949b425e05a6dbdfaec552ae81b5a7acbcec371` |
| `BENIGN_60_RUN_MANIFEST.json`, `BENIGN_60_RUN_SCENARIO_MATRIX.csv` | not listed | listed with their live hashes |
| encoding claim | "Both CSVs are UTF-8 with BOM" (wrong) | per-file truth - only the benign manifest has a BOM |
| split rule | "PROPOSED, not frozen" - 11/4/4 families, 19 families, `Akira` cross-OS | "FROZEN" - 12/4/4 families, 20 families, no cross-OS sharing |
| `expected_duration_seconds` | "`PENDING` until the runner's run window is frozen" | `60`, frozen |
| baselines | not stated | the R5-benign / V11-ransomware distinction, with the equivalence receipt |
| invocation contracts | not stated | the frozen per-family argv table and its authority |

Nothing outside this file changed. The pre-edit copy is kept at
`_PRE_D118_README_RECONCILE_20261112\README_100_RUN_MANIFEST.md`
(sha `63a98bbe961937bb16856cb6c48eb029e58e61857ab06f1fa33bde1eded1e47d`).
