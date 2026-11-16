<#
    RUN_WINDOWS_10_FAMILY_PREFLIGHT.ps1
    =====================================
    The 10-family Windows ransomware PREFLIGHT: one rehearsal of the complete official Windows
    path per qualified family (repetition A), executed ONE AT A TIME, sequentially, in campaign
    execution order.

    It drives the FROZEN production Windows controller (RANSOMWARE_Official_Run_Controller.ps1,
    RunMode=Preflight) - which consumes 0 of the 40 official campaign slots and writes to
    04_WINDOWS\RANSOMWARE\preflight_runs\ - one run per family:
        boot the WINDOWS guest from the frozen V11 baseline -> stage the sample read-only and
        the FROZEN 236-file canary corpus -> Sysmon+Procmon telemetry -> execute the sample
        under the 60 s bounded observation with the 90 s watchdog -> canary integrity -> pack
        -> power off -> revert to the Windows V11 baseline -> restore the host network.

    WHAT IS DIFFERENT FROM THE UBUNTU HALF, AND WHY IT IS RECORDED HERE
      * The Windows samples are launched with NO ARGUMENTS - that is the frozen Windows
        controller's behaviour, and NO Windows invocation contract has ever been frozen (the
        ten Windows families were never qualified; their binaries are guest-only, so no
        usage/disassembly evidence could be mined on the host). The driver therefore records
        the argv actually used as "NO_ARGUMENTS" on every run, and the per-family canary
        result is the evidence of whether the family targets the corpus at all.
      * A family whose behaviour is to encrypt broadly may damage the guest's own evidence
        area. That is contained - the guest is reverted - and a failed run is itself the
        finding that the family needs a path contract before its official runs. D-163 moved the
        corpus OUT of that evidence subtree (C:\RansomLab\Canary\<RUN>_<ATTEMPT>), because both
        families that walk C:\RansomLab skip the subtree containing their own image.
      * The canary corpus is the FROZEN common corpus (236 files, one per documented target
        extension), ported into the Windows executor in D-132 - the same corpus the Ubuntu
        half stages.

    The driver verifies every run's evidence before starting the next one. It HALTS ON THE
    FIRST FAILURE - EXCEPT for the D-147 preflight-only AV rule below - and it never modifies
    the manifests.

    D-147 (preflight only): an AV INTERVENTION IS A CHARACTERISATION OUTCOME, NOT A SERIES
    KILLER. If Defender/AV remediates malware-created content (or otherwise intervenes during
    the window), the run is recorded with av_intervened=true, the exact threat, resource,
    action and timestamp, and the status CHARACTERIZED_WITH_AV_INTERVENTION - it is NOT
    labelled a clean PASS, and the series CONTINUES to the next family so all ten Windows
    families are measured. The OFFICIAL Windows runs remain FAIL-CLOSED: this classification
    is applied only to a package whose run_mode is Preflight, the official mode never reaches
    this branch, and an AV-remediated family is not authorised for official execution merely
    because the preflight continued.

    Usage:
      powershell -NoProfile -ExecutionPolicy Bypass -File RUN_WINDOWS_10_FAMILY_PREFLIGHT.ps1 -DryRun
      powershell -NoProfile -ExecutionPolicy Bypass -File RUN_WINDOWS_10_FAMILY_PREFLIGHT.ps1
#>
[CmdletBinding()]
param(
    [string]$CampaignRoot = 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs',
    [int]$MaxRuns = 0,
    [switch]$DryRun,
    [string]$VerifyPackage = '',
    [double]$MinFreeGiB = 6.0
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PackageRoot = $PSScriptRoot
$Controller = Join-Path $PackageRoot 'RANSOMWARE_Official_Run_Controller.ps1'
$VmrunPath = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$VMwareGuiPath = 'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe'
$WindowsVmxPath = 'D:\Windows 11\Windows 11.vmx'
$UbuntuVmxPath = 'D:\Ubuntu 24.04\Ubuntu.vmx'
$WindowsSnapshot = 'P5G_V11_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261115'
$UbuntuSnapshot = 'P5G_V11_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261112'
$Manifest40 = Join-Path $CampaignRoot '01_SHARED\manifests\RANSOMWARE_40_RUN_MANIFEST.csv'
$Manifest100 = Join-Path $CampaignRoot '01_SHARED\manifests\CAMPAIGN_100_RUN_MANIFEST.csv'
$ContractManifest = Join-Path $CampaignRoot '01_SHARED\manifests\WINDOWS_INVOCATION_CONTRACTS.csv'
# D-156: the FROZEN per-family invocation/TARGET contract. It is a SEPARATE frozen artefact so
# the D-153 launch contract stays exactly as it was frozen; it adds the target (the argument
# vector and the evidence for it) that the launch contract could not express.
$TargetContractManifest = Join-Path $CampaignRoot '01_SHARED\manifests\WINDOWS_FAMILY_TARGET_CONTRACTS.csv'
$PreflightRoot = Join-Path $CampaignRoot '04_WINDOWS\RANSOMWARE\preflight_runs'
$OfficialRoot = Join-Path $CampaignRoot '04_WINDOWS\RANSOMWARE\official_runs'
$SummaryDir = Join-Path $CampaignRoot '01_SHARED\audit\WINDOWS_10_FAMILY_PREFLIGHT_20261112'

# every input is pinned; if any of them moved the preflight does not start
# D-156: the controller, the guest executor, the guest telemetry helper, the guest packer, the
# frozen target contract and the three new zero-execution tests are re-pinned at their D-156
# hashes (the telemetry order correction and the target contract changed all of them).
# D-161 (2026-11-14): ONLY the target-contract hash is re-pinned. It changes because the two
# falsified NON_ZERO_PREDICTED rows (RAN_WIN_04_A GreenBlood, RAN_WIN_06_A Akira) now carry the
# withdrawn-prediction record. corpus_root, argument templates, invocation modes and every other
# frozen input are unchanged; no execution logic changed in this script.
$Pinned = [ordered]@{
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RANSOMWARE_Official_Run_Controller.ps1' = 'a192a1de1f8a025a1872a8387647fce176afa2ce643396606c0d9df5aec4ffe8'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RANSOMWARE_Guest_Execute_Official.ps1' = '5fb5f0a51313ea2e413331e264f9227bfcd7e751a74ee07ded78831eea121732'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RANSOMWARE_Guest_Telemetry.ps1' = '5358cf32f273c58340d0096edaaad8ebcef37e7c0265bed92a644fe0bffbfd1c'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RANSOMWARE_Guest_Pack.ps1' = '1273f9dcaf0442befb141cce032a0684f5f097ef1ab1e2b5beca7e48b0b8eaed'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\NetworkBaseline.ps1' = 'd37f4a06d511f046cec0ea5dd98e496a66dc9f61343d6fd108658d2988a60e1e'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\HCQNativeBridge.ps1' = '312d8ef5a6376925b7b60c82722802ec50aecbc0c571029e1978cbc6fd55e33d'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RANSOMWARE_Guest_Antivirus.ps1' = '2991e3b8d2edcf3ae602cfbb71326b488bf2f90990947468cd30e3a592b9cbea'
    '01_SHARED\manifests\RANSOMWARE_40_RUN_MANIFEST.csv' = 'ed97c399ff87e19ecc1d8761ba8a20d7ac44cbf7b7fdfd80a4fcd7ff545d870d'
    '01_SHARED\manifests\CAMPAIGN_100_RUN_MANIFEST.csv' = '3f9d8ad577af830a87d23486341fb728b06a80902cb3fed2f7f8dd42c64fc843'
    '01_SHARED\manifests\WINDOWS_INVOCATION_CONTRACTS.csv' = '2c52f9d78f6c625c3acfe57c9a901f09ba9112ef6a461d9a8c6f6b5692e48636'
    '01_SHARED\manifests\WINDOWS_FAMILY_TARGET_CONTRACTS.csv' = '7c6a9e0704442ac12e3cd596b9fce07a5b95432a80281482f07f967f6b5ee056'
    '01_SHARED\scripts\host\audit\TEST_WINDOWS_INVOCATION_CONTRACT.ps1' = '0a822af52669f679ad883da66bde3ab3fc161599bd808b14a76485411d7087c9'
    '01_SHARED\scripts\host\audit\TEST_WINDOWS_TELEMETRY_ORDER.ps1' = '309af31f3354af66ccf4c5f12454eb4ac6680d5a38f72f46b8bbdba045bd639a'
    '01_SHARED\scripts\host\audit\TEST_WINDOWS_TIMING_DEFECT_NEGATIVE.ps1' = '03791abca4f519b9794374b661343cc68047caf8a1aa4cd2fafcc3b5a0cc1a3b'
    '01_SHARED\scripts\host\audit\TEST_WINDOWS_TARGET_CONTRACT.ps1' = 'c87c2c0d0c2c76640b195897c6f94facd0e02fb1e2e93e58d2ab6342d88fa600'
    '01_SHARED\scripts\host\qualification\VERIFY_WINDOWS_10_FAMILY_PREFLIGHT_PLAN.py' = '656205b5897ae76b490617cce13b8f4b3d2cd375868a04fb71e29ee54c987e7f'
    '01_SHARED\scripts\host\audit\WINDOWS_PREFLIGHT_ATTEMPT_LEDGER.py' = '61f5d59022ba9f72a9ff36ea6ef3afdae842b9d5cd240521a5ee76d5f21ce123'
    '01_SHARED\scripts\host\audit\TEST_WINDOWS_JOB_CONTAINMENT.ps1' = '7838311f11f85d220b7101ba763a547ea401d62c17018d677772cdecbadd89c3'
}

$Script:Results = @()

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw ('PREFLIGHT_FAILURE:' + $Message) } }
function SHA([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-Json([string]$Path, [object]$Object) {
    $d = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    [IO.File]::WriteAllText($Path, (($Object | ConvertTo-Json -Depth 20) + "`r`n"), (New-Object Text.UTF8Encoding($false)))
}
function Get-Field([object]$Obj, [string]$Name) {
    # D-134: read a receipt field defensively. A MISSING field must surface as a recorded
    # failure, never as a StrictMode crash that loses the whole series.
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}
function Has-Field([object]$Obj, [string]$Name) {
    # D-135: test the PROPERTY, not the value: an absent field and an EMPTY ARRAY (the PASS
    # case for canary_mismatches) are different things, and $null -eq @() is TRUE in PowerShell.
    if ($null -eq $Obj) { return $false }
    return ($null -ne $Obj.PSObject.Properties[$Name])
}
function Get-VmOn([string]$Vmrun, [string]$Vmx) {
    $out = & $Vmrun list 2>$null
    return (@($out | Where-Object { $_ -and ([string]$_).Trim().ToLowerInvariant() -eq $Vmx.ToLowerInvariant() }).Count -gt 0)
}
function Get-SnapshotName([string]$Vmx) {
    $a = @(Get-ChildItem -LiteralPath (Split-Path -Parent $Vmx) -Filter '*.vmsd' -File)
    if ($a.Count -ne 1) { throw ('VMSD_NOT_UNIQUE:' + $Vmx) }
    $lines = [IO.File]::ReadAllLines($a[0].FullName)
    $cur = ''; $uidToIndex = @{}; $indexToName = @{}
    foreach ($l in $lines) {
        $m = [regex]::Match($l, '^\s*snapshot\.current\s*=\s*"([^"]*)"'); if ($m.Success) { $cur = $m.Groups[1].Value }
        $m = [regex]::Match($l, '^\s*snapshot(\d+)\.uid\s*=\s*"([^"]*)"'); if ($m.Success) { $uidToIndex[$m.Groups[2].Value] = $m.Groups[1].Value }
        $m = [regex]::Match($l, '^\s*snapshot(\d+)\.displayName\s*=\s*"([^"]*)"'); if ($m.Success) { $indexToName[$m.Groups[1].Value] = $m.Groups[2].Value }
    }
    if ($uidToIndex.ContainsKey($cur) -and $indexToName.ContainsKey($uidToIndex[$cur])) { return $indexToName[$uidToIndex[$cur]] }
    return ''
}

# ------------------------------------------------------------------ administrator + pins
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Assert-True ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'
foreach ($rel in $Pinned.Keys) {
    $p = Join-Path $CampaignRoot $rel
    Assert-True (Test-Path -LiteralPath $p -PathType Leaf) ('PINNED_INPUT_MISSING:' + $rel)
    $actual = SHA $p
    Assert-True ($actual -ceq $Pinned[$rel]) ('PINNED_INPUT_DRIFT:' + $rel + ':expected=' + $Pinned[$rel] + ':actual=' + $actual)
}
Write-Host 'PREFLIGHT: every pinned input matches its recorded hash.' -ForegroundColor Green

# ------------------------------------------------------------------ the plan (10 families, repetition A)
$Rows40 = @(Import-Csv -LiteralPath $Manifest40)
$Rows100 = @(Import-Csv -LiteralPath $Manifest100)
# D-153: the frozen per-sample invocation contract. Nine of the ten Windows families are ordinary
# EXE images and keep the original NO_ARGUMENTS launch. WannaCry (W-R-07) is a PE32+ DLL - the
# read-only PE inventory proved IMAGE_FILE_DLL is set and the single export is PlayGame - so it is
# loaded through the system loader's documented export path. The SAMPLE, its hash, the timing
# window, the telemetry and the AV policy are unchanged; only the launch METHOD is per-sample.
$ContractRows = @(Import-Csv -LiteralPath $ContractManifest)
Assert-True ($ContractRows.Count -eq 20) ('INVOCATION_CONTRACT_ROW_COUNT:' + $ContractRows.Count)
# D-156: the target contract is pinned and validated before anything is executed.
$TargetRows = @(Import-Csv -LiteralPath $TargetContractManifest)
Assert-True ($TargetRows.Count -eq 20) ('TARGET_CONTRACT_ROW_COUNT:' + $TargetRows.Count)
$Plan = @()
foreach ($r in @($Rows40 | Where-Object { $_.platform -ceq 'Windows' -and $_.repetition -ceq 'A' } | Sort-Object { [int]$_.execution_order })) {
    Assert-True ([string]$r.snapshot_baseline -ceq $WindowsSnapshot) ('WINDOWS_ROW_BASELINE_NOT_R5:' + $r.run_id)
    $c = @($Rows100 | Where-Object { $_.run_id -ceq $r.run_id })
    Assert-True ($c.Count -eq 1) ('CAMPAIGN_ROW_NOT_FOUND:' + $r.run_id)
    Assert-True ([string]$c[0].snapshot_baseline -ceq $WindowsSnapshot) ('CAMPAIGN_ROW_BASELINE_NOT_R5:' + $r.run_id)
    # D-153: bind the contract row to this plan row, fail-closed.
    $ct = @($ContractRows | Where-Object { $_.run_id -ceq $r.run_id -and $_.sample_sha256 -ceq $r.sample_sha256 })
    Assert-True ($ct.Count -eq 1) ('INVOCATION_CONTRACT_NOT_FOUND:' + $r.run_id)
    $ct = $ct[0]
    Assert-True ([string]$ct.family_stratum -ceq [string]$r.family_stratum) ('INVOCATION_CONTRACT_FAMILY_MISMATCH:' + $r.run_id)
    Assert-True ([string]$ct.sample_arguments -ceq 'NO_ARGUMENTS') ('INVOCATION_CONTRACT_ARGUMENTS:' + $r.run_id)
    Assert-True ([string]$ct.invocation_mode -in @('DIRECT_EXE','RUNDLL32_EXPORT')) ('INVOCATION_CONTRACT_MODE:' + $r.run_id)
    if ([string]$ct.invocation_mode -ceq 'DIRECT_EXE') {
        Assert-True ([string]$ct.loader_path -eq '') ('INVOCATION_CONTRACT_DIRECT_LOADER:' + $r.run_id)
        Assert-True ([string]$ct.entry_point -eq '') ('INVOCATION_CONTRACT_DIRECT_ENTRY:' + $r.run_id)
        Assert-True ([string]$ct.image_type -ceq 'EXE') ('INVOCATION_CONTRACT_DIRECT_IMAGE_TYPE:' + $r.run_id)
    } else {
        Assert-True ([string]$ct.image_type -ceq 'DLL') ('INVOCATION_CONTRACT_DLL_IMAGE_TYPE:' + $r.run_id)
        Assert-True ([string]$ct.loader_path -ceq 'C:\Windows\System32\rundll32.exe') ('INVOCATION_CONTRACT_LOADER:' + $r.run_id)
        Assert-True ([string]$ct.entry_point -match '^[A-Za-z_][A-Za-z0-9_@?$]{0,127}$') ('INVOCATION_CONTRACT_ENTRY:' + $r.run_id)
    }
    # D-156: bind the frozen TARGET contract row to this plan row, fail-closed. The argument
    # vector is closed: NO_ARGUMENTS, or exactly one documented switch with the corpus
    # placeholder. Nothing else can be launched.
    $tg = @($TargetRows | Where-Object { $_.run_id -ceq $r.run_id -and $_.sample_sha256 -ceq $r.sample_sha256 })
    Assert-True ($tg.Count -eq 1) ('TARGET_CONTRACT_NOT_FOUND:' + $r.run_id)
    $tg = $tg[0]
    Assert-True ([string]$tg.family_stratum -ceq [string]$r.family_stratum) ('TARGET_CONTRACT_FAMILY_MISMATCH:' + $r.run_id)
    Assert-True ([string]$tg.invocation_mode -ceq [string]$ct.invocation_mode) ('TARGET_CONTRACT_INVOCATION_MODE_MISMATCH:' + $r.run_id)
    Assert-True ([string]$tg.loader_path -ceq [string]$ct.loader_path) ('TARGET_CONTRACT_LOADER_MISMATCH:' + $r.run_id)
    Assert-True ([string]$tg.entry_point -ceq [string]$ct.entry_point) ('TARGET_CONTRACT_ENTRY_MISMATCH:' + $r.run_id)
    $vec = [string]$tg.argument_vector_template
    Assert-True ($vec -match '^(NO_ARGUMENTS|--[a-z0-9_]+ <CANARY>)$') ('TARGET_CONTRACT_ARGUMENT_VECTOR_NOT_CLOSED:' + $r.run_id + ':' + $vec)
    $expectedTokens = $(if ($vec -ceq 'NO_ARGUMENTS') { 0 } else { 2 })
    Assert-True ([int]$tg.argument_tokens -eq $expectedTokens) ('TARGET_CONTRACT_ARGUMENT_TOKEN_COUNT:' + $r.run_id)
    Assert-True ([string]$tg.target_mechanism -in @('EXPLICIT_DOCUMENTED_SWITCH','DOCUMENTED_SCOPE_NO_EXPLICIT_TARGET','NO_ENCRYPTION_TARGET')) ('TARGET_CONTRACT_MECHANISM_UNKNOWN:' + $r.run_id)
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$tg.documented_scope_evidence)) ('TARGET_CONTRACT_EVIDENCE_MISSING:' + $r.run_id)
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$tg.expected_canary_effect)) ('TARGET_CONTRACT_EFFECT_MISSING:' + $r.run_id)
    $Plan += [pscustomobject]@{
        run_id = [string]$r.run_id
        execution_order = [int]$r.execution_order
        sample_run_id = [string]$r.sample_run_id
        family = [string]$r.family_stratum
        split = [string]$r.split
        repetition = [string]$r.repetition
        scenario_run_id = [string]$r.sample_run_id + '-' + [string]$r.repetition
        fixture_seed = [string]$c[0].fixture_seed
        sample_sha256 = [string]$r.sample_sha256
        sample_bytes = [string]$r.sample_bytes
        sample_guest_path = [string]$r.sample_guest_path
        # D-133: the frozen WINDOWS convention - Windows has no POSIX mode, and the manifest's
        # mode_octal column is EMPTY for the Windows rows (PowerShell rejects an empty string
        # for a mandatory parameter - that is what stopped the first attempt). The earlier
        # Windows ransomware pilot run passed and recorded mode_octal='N/A' with read_only='True'
        # (04_WINDOWS\RANSOMWARE\pilot_runs\RAN_WIN_01_A_...\evidence\sample_prepare_receipt.json).
        # The parameter is only recorded in the guest receipt; the executor verifies the
        # read-only ATTRIBUTE, never a POSIX mode.
        mode_octal = 'N/A'
        read_only = 'True'
        status = 'PENDING'
        invocation_contract = 'FROZEN_PER_SAMPLE:' + [string]$ct.invocation_mode
        invocation_mode = [string]$ct.invocation_mode
        invocation_image_type = [string]$ct.image_type
        invocation_loader_path = [string]$ct.loader_path
        invocation_entry_point = [string]$ct.entry_point
        argv_actually_used = 'NO_ARGUMENTS'
        # D-156: the frozen target contract.
        argument_vector_template = $vec
        argument_count = $expectedTokens
        target_mechanism = [string]$tg.target_mechanism
        target_evidence = [string]$tg.documented_scope_evidence
        target_expected_effect = [string]$tg.expected_canary_effect
    }
}
Assert-True ($Plan.Count -eq 10) ('PLAN_FAMILY_COUNT_NOT_10:' + $Plan.Count)
Assert-True ((@($Plan.family | Sort-Object -Unique).Count) -eq 10) 'PLAN_DISTINCT_FAMILIES_NOT_10'
# D-153: exactly one family uses the loader path, and it is WannaCry (W-R-07).
$LoaderPlans = @($Plan | Where-Object { $_.invocation_mode -ceq 'RUNDLL32_EXPORT' })
Assert-True ($LoaderPlans.Count -eq 1) ('INVOCATION_CONTRACT_LOADER_PLAN_COUNT:' + $LoaderPlans.Count)
Assert-True ([string]$LoaderPlans[0].run_id -ceq 'RAN_WIN_07_A') ('INVOCATION_CONTRACT_LOADER_PLAN_RUN_ID:' + [string]$LoaderPlans[0].run_id)
Assert-True ([string]$LoaderPlans[0].family -ceq 'WannaCry') ('INVOCATION_CONTRACT_LOADER_PLAN_FAMILY:' + [string]$LoaderPlans[0].family)
Assert-True ([string]$LoaderPlans[0].invocation_entry_point -ceq 'PlayGame') ('INVOCATION_CONTRACT_LOADER_PLAN_ENTRY:' + [string]$LoaderPlans[0].invocation_entry_point)
Assert-True ((@($Plan | Where-Object { $_.invocation_mode -ceq 'DIRECT_EXE' }).Count) -eq 9) 'INVOCATION_CONTRACT_DIRECT_PLAN_COUNT'

Write-Host ''
Write-Host ('=== WINDOWS 10-FAMILY RANSOMWARE PREFLIGHT PLAN ({0} families, repetition A) ===' -f $Plan.Count) -ForegroundColor Cyan
Write-Host ('{0,-5} {1,-16} {2,-16} {3,-11} {4,-6} {5}' -f 'ord', 'run_id', 'family', 'split', 'rep', 'fixture seed')
foreach ($p in $Plan) {
    Write-Host ('{0,-5} {1,-16} {2,-16} {3,-11} {4,-6} {5}' -f $p.execution_order, $p.run_id, $p.family, $p.split, $p.repetition, $p.fixture_seed)
}
Write-Host ''
Write-Host 'NOTE (D-153): the per-sample invocation contract is frozen in 01_SHARED\manifests\WINDOWS_INVOCATION_CONTRACTS.csv.' -ForegroundColor Yellow
Write-Host '      Nine families are EXE images and keep the original NO_ARGUMENTS direct launch.' -ForegroundColor Yellow
Write-Host '      WannaCry (W-R-07) is a DLL (IMAGE_FILE_DLL) and is loaded through rundll32.exe ...,PlayGame.' -ForegroundColor Yellow
Write-Host '      The sample, its hash, the timing window, the telemetry and the AV policy are unchanged.' -ForegroundColor Yellow
Write-Host 'NOTE (D-156): the per-family invocation/TARGET contract is frozen in 01_SHARED\manifests\WINDOWS_FAMILY_TARGET_CONTRACTS.csv.' -ForegroundColor Yellow
Write-Host ('      {0,-5} {1,-16} {2,-14} {3,-34} {4}' -f 'ord', 'run_id', 'family', 'argument vector', 'target mechanism') -ForegroundColor Yellow
foreach ($p in $Plan) {
    Write-Host ('      {0,-5} {1,-16} {2,-14} {3,-34} {4}' -f $p.execution_order, $p.run_id, $p.family, $p.argument_vector_template, $p.target_mechanism) -ForegroundColor Yellow
}
Write-Host '      NO_ARGUMENTS means the binary documents no target argument: the family is measured, not forced.' -ForegroundColor Yellow
Write-Host 'NOTE (D-156): the capture is stopped INSIDE the guest executor (sample -> tail -> STOP CAPTURE),' -ForegroundColor Yellow
Write-Host '      so no lab restore, verification, packing or transfer can be inside the capture window.' -ForegroundColor Yellow

if ($DryRun) { Write-Host 'DRY RUN: nothing was executed; no slot was consumed.' -ForegroundColor Yellow; exit 0 }

# ------------------------------------------------------------------ the evidence verifier
# D-135: the per-run verification is a FUNCTION so it can be exercised against a real evidence
# package with NO execution (-VerifyPackage). EVERY field is read through Get-Field, the
# WINDOWS receipt shapes are used, and a missing receipt or field is a RECORDED failure.
function Read-Receipt([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Test-RunEvidence {
    param([string]$RunDir, [string]$ExpectedInvocationMode = '', [string]$ExpectedArgumentVector = '')
    $r = [ordered]@{
        ok = $true; failure = ''; official_slots_consumed = ''; termination_mode = ''; watchdog_fired = ''
        sample_exit_code = ''; sample_exit_code_class = ''; actual_execution_seconds = ''
        sample_runtime_seconds = ''; kill_settle_seconds = ''; canary_total = ''; canaries_modified = ''
        canary_all_intact = ''; telemetry_rows = ''; canary_root = ''
        canaries_missing = ''; canaries_hash_mismatched = ''
        av_interference_mitigated = ''; antivirus_summary = ''; antivirus_detections = ''
        antivirus_remediated = ''; antivirus_behavioural = ''; antivirus_remediated_other = ''
        antivirus_threat_names = ''
        # D-147: the AV characterisation (preflight only).
        av_intervened = ''; av_status_class = ''; av_intervention = ''
        av_intervention_threats = ''; av_intervention_resources = ''
        av_intervention_actions = ''; av_intervention_timestamps = ''
        # D-146/D-147: the frozen timing semantics, named explicitly (values are unchanged).
        scientific_runtime_seconds = ''; termination_overhead_seconds = ''
        telemetry_tail_seconds = ''; finalization_orchestration_seconds = ''
        # D-156: the capture-boundary semantics.
        post_workload_capture_seconds = ''; capture_stop_overhead_seconds = ''; capture_window_seconds = ''
        capture_start_utc = ''; capture_stop_utc = ''; capture_closed_before_restore = ''
        lab_restore_inside_capture = ''; telemetry_restore_seconds = ''; lab_restore_seconds = ''
        # D-153: the invocation contract the run actually used.
        invocation_mode = ''; invocation_entry_point = ''; invocation_loader_path = ''
        sample_arguments = ''; sample_image_dll = ''
        argument_vector_contract = ''; resolved_argument_vector = ''; target_mechanism = ''
    }
    $rr = Read-Receipt (Join-Path $RunDir 'RUN_RESULT.json')
    $pr = Read-Receipt (Join-Path $RunDir 'evidence\sample_prepare_receipt.json')
    $sx = Read-Receipt (Join-Path $RunDir 'evidence\sample_execute_receipt.json')
    $ci = Read-Receipt (Join-Path $RunDir 'evidence\canary_integrity_receipt.json')
    $tc = Read-Receipt (Join-Path $RunDir 'evidence\telemetry_capture_receipt.json')
    $rcv = Read-Receipt (Join-Path $RunDir 'recovery\POST_RECOVERY_VERIFICATION.json')
    $fv = Read-Receipt (Join-Path $RunDir 'RUN_FULL_VERIFICATION.json')
    if ($null -eq $rr -or $null -eq $pr -or $null -eq $sx -or $null -eq $ci -or $null -eq $tc -or $null -eq $rcv) {
        $r.ok = $false; $r.failure = 'RECEIPT_MISSING_OR_UNREADABLE'; return $r
    }

    # ---- the run result (the field names are the same on both OSes) ----
    $r.official_slots_consumed = [string](Get-Field $rr 'official_campaign_slots_consumed')
    $r.termination_mode = [string](Get-Field $rr 'termination_mode')
    $r.watchdog_fired = [string](Get-Field $rr 'watchdog_fired')
    $r.watchdog_armed = [string](Get-Field $rr 'watchdog_armed')
    $r.sample_exit_code = [string](Get-Field $rr 'exit_code')
    # D-139: the exit code's class (NORMAL / WINDOWS_NTSTATUS_CRASH / WATCHDOG_KILL) is recorded.
    $r.sample_exit_code_class = [string](Get-Field $rr 'exit_code_class')
    $r.actual_execution_seconds = [string](Get-Field $rr 'actual_execution_seconds')
    # D-140: the sample's runtime and the lab's kill/settle overhead are recorded separately.
    $r.sample_runtime_seconds = [string](Get-Field $rr 'sample_runtime_seconds')
    $r.kill_settle_seconds = [string](Get-Field $rr 'kill_settle_seconds')
    # D-147: the four frozen timing semantics under their explicit names. These are ALIASES of
    # the values above - no timing value is changed: the scientific runtime (the sample's own
    # observable runtime inside the 60 s window), the termination overhead (the lab's teardown
    # after the deadline, bounded by the 90 s emergency watchdog budget), the fixed 10 s
    # telemetry tail, and the finalisation orchestration (Procmon stop + capture assembly).
    $r.scientific_runtime_seconds = $r.sample_runtime_seconds
    $r.termination_overhead_seconds = $r.kill_settle_seconds
    $r.telemetry_tail_seconds = [string](Get-Field $rr 'post_tail_seconds')
    $r.finalization_orchestration_seconds = [string](Get-Field $rr 'telemetry_finalize_seconds')
    # D-156: the capture-boundary values, read from the run result.
    $r.post_workload_capture_seconds = [string](Get-Field $rr 'post_workload_capture_seconds')
    $r.capture_stop_overhead_seconds = [string](Get-Field $rr 'capture_stop_overhead_seconds')
    $r.capture_window_seconds = [string](Get-Field $rr 'capture_window_seconds')
    $r.capture_start_utc = [string](Get-Field $rr 'capture_start_utc')
    $r.capture_stop_utc = [string](Get-Field $rr 'capture_stop_utc')
    $r.capture_closed_before_restore = [string](Get-Field $rr 'capture_closed_before_restore')
    $r.lab_restore_inside_capture = [string](Get-Field $rr 'lab_restore_inside_capture')
    $r.telemetry_restore_seconds = [string](Get-Field $rr 'telemetry_restore_seconds')
    $r.lab_restore_seconds = [string](Get-Field $rr 'lab_restore_seconds')
    if ([string](Get-Field $rr 'status') -cne 'PASS') { $r.ok = $false; $r.failure = 'RUN_RESULT_NOT_PASS' }
    if ([string](Get-Field $rr 'run_mode') -cne 'Preflight') { $r.ok = $false; $r.failure = 'RUN_MODE_NOT_PREFLIGHT' }
    if ([bool](Get-Field $rr 'official_run')) { $r.ok = $false; $r.failure = 'OFFICIAL_RUN_FLAG_SET' }
    if ([int](Get-Field $rr 'official_campaign_slots_consumed') -ne 0) { $r.ok = $false; $r.failure = 'SLOT_COUNT_NOT_ZERO' }
    if (-not [bool](Get-Field $rr 'watchdog_armed')) { $r.ok = $false; $r.failure = 'WATCHDOG_NOT_ARMED' }
    if (-not [bool](Get-Field $rr 'recovery_verified')) { $r.ok = $false; $r.failure = 'RECOVERY_NOT_VERIFIED' }
    # D-135: a MISSING boolean casts to $false and a MISSING int to 0, so the value checks
    # alone cannot tell an absent field from a false/zero one. Every critical field is
    # therefore also tested for PRESENCE.
    foreach ($f in @('status','run_mode','official_run','official_campaign_slots_consumed','watchdog_armed','recovery_verified')) {
        if (-not (Has-Field $rr $f)) { $r.ok = $false; $r.failure = 'RUN_RESULT_FIELD_MISSING' }
    }

    # ---- D-153: the invocation contract the run actually used ----
    # The guest receipt is the authority: it records the mode, the loader, the export and whether
    # the staged image was a DLL. The run must agree with the frozen contract row for this family.
    $r.invocation_mode = [string](Get-Field $sx 'invocation_mode')
    $r.invocation_entry_point = [string](Get-Field $sx 'entry_point')
    $r.invocation_loader_path = [string](Get-Field $sx 'loader_path')
    $r.sample_arguments = [string](Get-Field $sx 'sample_arguments')
    $r.sample_image_dll = [string](Get-Field $sx 'sample_image_dll')
    # A package produced BEFORE D-153 carries none of the contract fields; it is verified as it
    # was, and the contract is enforced where it can be enforced: on every LIVE preflight run
    # (the driver passes the expected mode) and by the controller, which refuses a guest receipt
    # whose mode does not match the frozen contract row.
    $contractFieldsPresent = ((Has-Field $sx 'invocation_mode') -or (Has-Field $sx 'sample_arguments') -or (Has-Field $sx 'sample_image_dll'))
    if ($contractFieldsPresent -or $ExpectedInvocationMode -ne '') {
        foreach ($f in @('invocation_mode','entry_point','loader_path','sample_arguments','sample_image_dll')) {
            if (-not (Has-Field $sx $f)) { if ($r.failure -eq '') { $r.failure = 'SAMPLE_RECEIPT_INVOCATION_FIELD_MISSING' }; $r.ok = $false }
        }
        if ([string](Get-Field $sx 'sample_arguments') -cne 'NO_ARGUMENTS' -and $ExpectedArgumentVector -eq '') {
            if ($r.failure -eq '') { $r.failure = 'SAMPLE_ARGUMENTS_NOT_NO_ARGUMENTS' }; $r.ok = $false
        }
        # D-156: the argument vector the guest actually applied must be EXACTLY the frozen
        # contract template with <CANARY> bound to the corpus root the prepare receipt records.
        if ($ExpectedArgumentVector -ne '') {
            $r.argument_vector_contract = [string](Get-Field $sx 'argument_vector_contract')
            $r.resolved_argument_vector = [string](Get-Field $sx 'sample_arguments')
            $r.target_mechanism = [string](Get-Field $sx 'target_mechanism')
            if (-not (Has-Field $sx 'argument_vector_contract')) { if ($r.failure -eq '') { $r.failure = 'ARGUMENT_VECTOR_CONTRACT_FIELD_MISSING' }; $r.ok = $false }
            elseif ($r.argument_vector_contract -cne $ExpectedArgumentVector) {
                if ($r.failure -eq '') { $r.failure = 'ARGUMENT_VECTOR_CONTRACT_MISMATCH' }; $r.ok = $false
            }
            $corpusRoot = [string](Get-Field $pr 'canary_root')
            if ($corpusRoot -eq '') { if ($r.failure -eq '') { $r.failure = 'CORPUS_ROOT_MISSING' }; $r.ok = $false }
            else {
                $expectedResolved = ($ExpectedArgumentVector -replace '<CANARY>', $corpusRoot)
                if ($r.resolved_argument_vector -cne $expectedResolved) {
                    if ($r.failure -eq '') { $r.failure = 'RESOLVED_ARGUMENT_VECTOR_MISMATCH' }; $r.ok = $false
                }
            }
        }
        if ($ExpectedInvocationMode -ne '') {
            if ([string](Get-Field $sx 'invocation_mode') -cne $ExpectedInvocationMode) {
                if ($r.failure -eq '') { $r.failure = 'INVOCATION_MODE_MISMATCH' }; $r.ok = $false
            }
        }
        if ([string](Get-Field $sx 'invocation_mode') -ceq 'RUNDLL32_EXPORT') {
            if (-not [bool](Get-Field $sx 'sample_image_dll')) { if ($r.failure -eq '') { $r.failure = 'SAMPLE_NOT_A_DLL' }; $r.ok = $false }
            if ([bool](Get-Field $sx 'staged_sample_launched_directly')) { if ($r.failure -eq '') { $r.failure = 'DLL_LAUNCHED_DIRECTLY' }; $r.ok = $false }
            if ([string](Get-Field $sx 'entry_point') -ceq '') { if ($r.failure -eq '') { $r.failure = 'ENTRY_POINT_EMPTY' }; $r.ok = $false }
        } elseif ([string](Get-Field $sx 'invocation_mode') -ceq 'DIRECT_EXE') {
            if ([bool](Get-Field $sx 'sample_image_dll')) { if ($r.failure -eq '') { $r.failure = 'EXE_CONTRACT_ON_A_DLL' }; $r.ok = $false }
            if (-not [bool](Get-Field $sx 'staged_sample_launched_directly')) { if ($r.failure -eq '') { $r.failure = 'EXE_NOT_LAUNCHED_DIRECTLY' }; $r.ok = $false }
        }
    }

    # ---- the prepare receipt ----
    if ([string](Get-Field $pr 'status') -cne 'PASS') { $r.ok = $false; $r.failure = 'SAMPLE_PREPARE_NOT_PASS' }
    if (-not [bool](Get-Field $pr 'isolation_verified')) { $r.ok = $false; $r.failure = 'GUEST_ISOLATION_NOT_VERIFIED' }
    if ([int](Get-Field $pr 'canary_count') -ne 236) { $r.ok = $false; $r.failure = 'CANARY_COUNT_NOT_236' }
    $r.canary_root = [string](Get-Field $pr 'canary_root')
    # D-163: the corpus root must be the FROZEN exposure root - a sibling of
    # C:\RansomLab\RansomwareOfficial - and never a child of this run's work subtree. Without
    # this check a regressed executor would silently return the measured 0/236 placement.
    if ($r.canary_root -notmatch '^C:\\RansomLab\\Canary\\[A-Za-z0-9_]+$') { if ($r.failure -eq '') { $r.failure = 'CANARY_ROOT_NOT_THE_FROZEN_EXPOSURE_ROOT' }; $r.ok = $false }
    if ($r.canary_root -like '*\RansomwareOfficial\*') { if ($r.failure -eq '') { $r.failure = 'CANARY_ROOT_INSIDE_RUN_SUBTREE' }; $r.ok = $false }
    foreach ($f in @('status','isolation_verified','canary_count','canary_root')) {
        if (-not (Has-Field $pr $f)) { $r.ok = $false; $r.failure = 'SAMPLE_PREPARE_FIELD_MISSING' }
    }

    # ---- the sample-run receipt ----
    if (-not [bool](Get-Field $sx 'watchdog_armed')) { $r.ok = $false; $r.failure = 'WATCHDOG_NOT_ARMED' }
    if (-not (Has-Field $sx 'termination_mode')) { $r.ok = $false; $r.failure = 'SAMPLE_RUN_RECEIPT_FIELD_MISSING' }
    if (-not (Has-Field $sx 'actual_execution_seconds')) { $r.ok = $false; $r.failure = 'SAMPLE_RUN_RECEIPT_FIELD_MISSING' }
    foreach ($f in @('watchdog_armed','termination_mode','actual_execution_seconds')) {
        if (-not (Has-Field $sx $f)) { $r.ok = $false; $r.failure = 'SAMPLE_RUN_RECEIPT_FIELD_MISSING' }
    }

    # ---- D-156: the capture boundary ----
    # The capture must have been closed INSIDE the guest, before any host-side restore, and the
    # post-workload capture period must be inside the benign-equivalent envelope.
    if (-not (Has-Field $sx 'capture_stop_status')) { $r.ok = $false; $r.failure = 'CAPTURE_STOP_STATUS_FIELD_MISSING' }
    elseif ([string](Get-Field $sx 'capture_stop_status') -cne 'PASS') { $r.ok = $false; $r.failure = 'CAPTURE_STOP_NOT_COMPLETED' }
    if (-not (Has-Field $sx 'capture_closed_inside_guest')) { $r.ok = $false; $r.failure = 'CAPTURE_CLOSED_FLAG_MISSING' }
    elseif (-not [bool](Get-Field $sx 'capture_closed_inside_guest')) { $r.ok = $false; $r.failure = 'CAPTURE_NOT_CLOSED_INSIDE_THE_GUEST' }
    if (-not (Has-Field $sx 'lab_restore_inside_capture')) { $r.ok = $false; $r.failure = 'LAB_RESTORE_INSIDE_CAPTURE_FLAG_MISSING' }
    elseif ([bool](Get-Field $sx 'lab_restore_inside_capture')) { $r.ok = $false; $r.failure = 'LAB_RESTORE_INSIDE_CAPTURE' }
    if (-not (Has-Field $sx 'capture_stop_utc')) { $r.ok = $false; $r.failure = 'CAPTURE_STOP_UTC_MISSING' }
    if (-not (Has-Field $sx 'sample_stop_utc')) { $r.ok = $false; $r.failure = 'SAMPLE_STOP_UTC_MISSING' }
    # The post-workload capture period is the bounded tail plus the stop overhead: ~10-15 s.
    $pwc = Get-Field $sx 'post_workload_capture_seconds'
    if ($null -eq $pwc) { $r.ok = $false; $r.failure = 'POST_WORKLOAD_CAPTURE_SECONDS_MISSING' }
    else {
        $pwcv = 0.0
        if (-not [double]::TryParse([string]$pwc, [ref]$pwcv)) { $r.ok = $false; $r.failure = 'POST_WORKLOAD_CAPTURE_SECONDS_NOT_A_NUMBER' }
        elseif ($pwcv -le 0 -or $pwcv -gt 15.0) { $r.ok = $false; $r.failure = 'POST_WORKLOAD_CAPTURE_OUTSIDE_THE_ENVELOPE' }
    }
    # The capture window must be bounded: the sample's window + the tail + the stop overhead.
    $cwin = Get-Field $rr 'capture_window_seconds'
    if ($null -eq $cwin) { $r.ok = $false; $r.failure = 'CAPTURE_WINDOW_SECONDS_MISSING' }
    else {
        $cwv = 0.0
        if (-not [double]::TryParse([string]$cwin, [ref]$cwv)) { $r.ok = $false; $r.failure = 'CAPTURE_WINDOW_SECONDS_NOT_A_NUMBER' }
        elseif ($cwv -le 0 -or $cwv -gt 195.0) { $r.ok = $false; $r.failure = 'CAPTURE_WINDOW_OUTSIDE_THE_ACCEPTANCE_BUDGET' }
    }
    if (-not (Has-Field $rr 'capture_closed_before_restore')) { $r.ok = $false; $r.failure = 'CAPTURE_CLOSED_BEFORE_RESTORE_FIELD_MISSING' }
    elseif (-not [bool](Get-Field $rr 'capture_closed_before_restore')) { $r.ok = $false; $r.failure = 'CAPTURE_NOT_CLOSED_BEFORE_THE_RESTORE' }
    if (-not (Has-Field $rr 'lab_restore_inside_capture')) { $r.ok = $false; $r.failure = 'LAB_RESTORE_INSIDE_CAPTURE_FIELD_MISSING' }
    elseif ([bool](Get-Field $rr 'lab_restore_inside_capture')) { $r.ok = $false; $r.failure = 'LAB_RESTORE_INSIDE_CAPTURE' }

    # ---- the canary receipt (the WINDOWS shape) ----
    $r.canary_total = [string](Get-Field $ci 'canary_total')
    $r.canaries_modified = [string]@((Get-Field $ci 'canary_mismatches') | Where-Object { $null -ne $_ }).Count
    $r.canary_all_intact = [string](Get-Field $ci 'canary_all_intact')
    # D-163: missing and content-changed canaries are recorded separately (they are different
    # observations). Neither is a gate: canary modification is not a PASS/FAIL condition.
    $r.canaries_missing = [string]@((Get-Field $ci 'canary_missing') | Where-Object { $null -ne $_ }).Count
    $r.canaries_hash_mismatched = [string]@((Get-Field $ci 'canary_hash_mismatches') | Where-Object { $null -ne $_ }).Count
    if (-not (Has-Field $ci 'canary_total')) { $r.ok = $false; $r.failure = 'CANARY_RECEIPT_FIELD_MISSING' }
    if (-not (Has-Field $ci 'canary_mismatches')) { $r.ok = $false; $r.failure = 'CANARY_RECEIPT_FIELD_MISSING' }
    if ([string](Get-Field $ci 'canary_root') -cne $r.canary_root) { $r.ok = $false; $r.failure = 'CANARY_VERIFY_ROOT_MISMATCH' }

    # ---- the telemetry receipt (the WINDOWS shape: a Procmon PML + a Sysmon tree, no row count) ----
    $pmlBytes = Get-Field $tc 'capture_pml_bytes'
    $sysmonBytes = Get-Field $tc 'sysmon_process_tree_csv_bytes'
    $eventLoss = Get-Field $tc 'event_loss_count'
    $r.telemetry_rows = ('pml_bytes=' + [string]$pmlBytes + '; sysmon_tree_csv_bytes=' + [string]$sysmonBytes + '; event_loss=' + [string]$eventLoss)
    if (-not (Has-Field $tc 'capture_pml_bytes') -or -not (Has-Field $tc 'event_loss_count')) { $r.ok = $false; $r.failure = 'TELEMETRY_RECEIPT_FIELD_MISSING' }
    if ([int]$eventLoss -ne 0) { $r.ok = $false; $r.failure = 'TELEMETRY_EVENT_LOSS_NONZERO' }
    if (-not [bool](Get-Field $tc 'telemetry_ready_before_sample')) { $r.ok = $false; $r.failure = 'TELEMETRY_NOT_READY_BEFORE_SAMPLE' }
    if (-not [bool](Get-Field $tc 'telemetry_helper_finalized')) { $r.ok = $false; $r.failure = 'TELEMETRY_NOT_FINALIZED' }
    foreach ($f in @('capture_pml_bytes','event_loss_count','telemetry_ready_before_sample','telemetry_helper_finalized')) {
        if (-not (Has-Field $tc $f)) { $r.ok = $false; $r.failure = 'TELEMETRY_RECEIPT_FIELD_MISSING' }
    }

    # ---- the recovery receipt (the WINDOWS shape: network_exactly_restored) ----
    if ([string](Get-Field $rcv 'status') -cne 'PASS') { $r.ok = $false; $r.failure = 'RECOVERY_NOT_PASS' }
    if ([string](Get-Field $rcv 'windows_snapshot') -cne $WindowsSnapshot) { $r.ok = $false; $r.failure = 'RECOVERY_WINDOWS_SNAPSHOT_NOT_R5' }
    $netRestored = Get-Field $rcv 'network_exactly_restored'
    if (-not (Has-Field $rcv 'network_exactly_restored')) { $r.ok = $false; $r.failure = 'RECOVERY_RECEIPT_FIELD_MISSING' }
    elseif (-not [bool]$netRestored) { $r.ok = $false; $r.failure = 'HOST_NETWORK_NOT_RESTORED' }
    foreach ($f in @('status','windows_snapshot','network_exactly_restored')) {
        if (-not (Has-Field $rcv $f)) { $r.ok = $false; $r.failure = 'RECOVERY_RECEIPT_FIELD_MISSING' }
    }

    # ---- the antivirus state (D-136) ----
    # The guest antivirus is an environmental confounder: the Ubuntu guest has none, so a
    # Windows run in which it intercepts the sample measures the antivirus, not the malware.
    # The PRE receipt must exist and must record that the AV INTERFERENCE WAS MITIGATED for the
    # analysis window; the POST receipt must exist and must show no NEW detection.
    $avPre = Read-Receipt (Join-Path $RunDir 'evidence\antivirus_state.json')
    $avPost = Read-Receipt (Join-Path $RunDir 'evidence\antivirus_state_post.json')
    if ($null -eq $avPre) { if ($r.failure -eq '') { $r.failure = 'ANTIVIRUS_STATE_MISSING'; $r.ok = $false } }
    else {
        if (-not (Has-Field $avPre 'av_interference_mitigated')) { if ($r.failure -eq '') { $r.failure = 'AV_STATE_FIELD_MISSING'; $r.ok = $false } }
        elseif (-not [bool](Get-Field $avPre 'av_interference_mitigated')) { if ($r.failure -eq '') { $r.failure = 'AV_INTERFERENCE_NOT_MITIGATED'; $r.ok = $false } }
        $r.antivirus_summary = [string](Get-Field $avPre 'antivirus_summary')
        $r.av_interference_mitigated = [string](Get-Field $avPre 'av_interference_mitigated')
    }
    if ($null -eq $avPost) { if ($r.failure -eq '') { $r.failure = 'ANTIVIRUS_POST_STATE_MISSING'; $r.ok = $false } }
    else {
        # D-137: a detection is judged by what the antivirus DID with it. A REMEDIATED
        # detection is an intervention - the malware's file was blocked/cleaned - so the
        # measurement is contaminated and the run fails. A detection that was NOT remediated is
        # EVIDENCE about the malware and is recorded in the run summary.
        $preKeys = @()
        if ($null -ne $avPre) {
            foreach ($d in @((Get-Field $avPre 'detections'))) {
                $preKeys += ([string](Get-Field $d 'threat_id') + '|' + [string](Get-Field $d 'detection_time') + '|' + (@((Get-Field $d 'resources')) -join ','))
            }
        }
        # D-142/D-147: a detection ON THE SAMPLE (a behavioural rule - Defender's GenRansom
        # stopped the OpnKey run after 23.0 s) is a FINDING about the family: the antivirus
        # stopped the malware, the observation is truncated but complete and honestly recorded.
        # D-147 (PREFLIGHT ONLY): an AV INTERVENTION - any new detection whose remediation
        # action SUCCEEDED, whether on the sample or on the malware's own dropped content - is a
        # CHARACTERISATION OUTCOME, not a series killer: it is recorded in full and the run is
        # labelled CHARACTERIZED_WITH_AV_INTERVENTION (never a clean PASS), and the series
        # continues to the next family. A package that is NOT a preflight run stays FAIL-CLOSED.
        $stagedSample = [string](Get-Field (Read-Receipt (Join-Path $RunDir 'evidence\sample_prepare_receipt.json')) 'sample_staged_path')
        $isPreflightPackage = ([string](Get-Field $rr 'run_mode') -ceq 'Preflight')
        $newDetections = @()
        $interventionDetails = @()
        $remediated = 0
        $remediatedOther = 0
        $behavioural = 0
        foreach ($d in @((Get-Field $avPost 'detections'))) {
            $k = ([string](Get-Field $d 'threat_id') + '|' + [string](Get-Field $d 'detection_time') + '|' + (@((Get-Field $d 'resources')) -join ','))
            if ($preKeys -notcontains $k) {
                $newDetections += $d
                $resList = @((Get-Field $d 'resources') | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
                $res = ($resList -join ' ')
                $onSample = ($stagedSample -ne '') -and ($res -like ('*' + $stagedSample + '*'))
                $actionSuccess = [bool](Get-Field $d 'action_success')
                if ($onSample) { $behavioural++ }
                if ($actionSuccess) {
                    $remediated++
                    if (-not $onSample) { $remediatedOther++ }
                    $interventionDetails += [ordered]@{
                        threat_name = [string](Get-Field $d 'threat_name')
                        threat_id = [string](Get-Field $d 'threat_id')
                        resources = @($resList)
                        action = [string](Get-Field $d 'action')
                        action_success = $actionSuccess
                        remediation = $(if ($actionSuccess) { 'REMEDIED_BY_AV' } else { 'DETECTION_ONLY' })
                        detection_time = [string](Get-Field $d 'detection_time')
                        on_sample = [bool]$onSample
                    }
                }
            }
        }
        $r.antivirus_detections = [string]@($newDetections).Count
        $r.antivirus_remediated = [string]$remediated
        $r.antivirus_behavioural = [string]$behavioural
        $r.antivirus_remediated_other = [string]$remediatedOther
        $r.antivirus_threat_names = (@($newDetections | ForEach-Object { [string](Get-Field $_ 'threat_name') }) -join ',')
        if ($remediated -gt 0 -and $isPreflightPackage) {
            $r.av_intervened = 'True'
            $r.av_status_class = 'CHARACTERIZED_WITH_AV_INTERVENTION'
            $r.av_intervention = (ConvertTo-Json -InputObject @($interventionDetails) -Depth 8 -Compress)
            $r.av_intervention_threats = (@($interventionDetails | ForEach-Object { [string]$_.threat_name }) -join '; ')
            $r.av_intervention_resources = (@($interventionDetails | ForEach-Object { @($_.resources) -join ' | ' }) -join '; ')
            $r.av_intervention_actions = (@($interventionDetails | ForEach-Object {
                $a = [string]$_.action
                if ([string]::IsNullOrWhiteSpace($a)) { $a = [string]$_.remediation } else { $a = $a + ' (' + [string]$_.remediation + ')' }
                $a
            }) -join '; ')
            $r.av_intervention_timestamps = (@($interventionDetails | ForEach-Object { [string]$_.detection_time }) -join '; ')
        }
        elseif ($remediated -gt 0) {
            # OFFICIAL (and any non-preflight) package: the frozen fail-closed rule is unchanged.
            if ($r.failure -eq '') { $r.failure = 'ANTIVIRUS_REMEDIATED_DURING_RUN'; $r.ok = $false }
        }
    }

    # ---- the archive and the package self-verification ----
    if (-not (Test-Path -LiteralPath (Join-Path $RunDir 'capture_archive.zip') -PathType Leaf)) { $r.ok = $false; $r.failure = 'CAPTURE_ARCHIVE_MISSING' }
    if ($null -eq $fv) { $r.ok = $false; $r.failure = 'PACKAGE_SELF_VERIFICATION_MISSING' }
    elseif ([string](Get-Field $fv 'status') -cne 'PASS' -or [int](Get-Field $fv 'fail') -ne 0) { $r.ok = $false; $r.failure = 'PACKAGE_SELF_VERIFICATION_NOT_PASS' }
    # D-147: a run that passed every hard gate with no AV intervention is a clean PASS; one whose
    # only deviation is a recorded AV intervention carries CHARACTERIZED_WITH_AV_INTERVENTION.
    if ($r.ok -and [string]$r.av_status_class -eq '') { $r.av_status_class = 'PASS' }
    return $r
}

# D-135: exercise the evidence verification against an existing package - NO execution.
if ($VerifyPackage -ne '') {
    Assert-True (Test-Path -LiteralPath $VerifyPackage -PathType Container) 'VERIFY_PACKAGE_DIR_MISSING'
    $v = Test-RunEvidence -RunDir $VerifyPackage
    Write-Host ('VERIFY PACKAGE: ' + $VerifyPackage)
    # D-147: an AV-characterised preflight package is NOT a clean PASS, but it is not a failure.
    $vResult = if (-not $v.ok) { 'FAIL - ' + $v.failure }
               elseif ([string]$v.av_status_class -eq 'CHARACTERIZED_WITH_AV_INTERVENTION') { 'CHARACTERIZED_WITH_AV_INTERVENTION' }
               else { 'PASS' }
    Write-Host ('  result      : ' + $vResult)
    Write-Host ('  termination : ' + $v.termination_mode + '   slots: ' + $v.official_slots_consumed)
    Write-Host ('  canaries    : ' + $v.canaries_modified + '/' + $v.canary_total + '   intact: ' + $v.canary_all_intact)
    Write-Host ('  telemetry   : ' + $v.telemetry_rows)
    Write-Host ('  av          : intervened=' + $v.av_intervened + ' detections=' + $v.antivirus_detections + ' threat=' + $v.av_intervention_threats + ' resource=' + $v.av_intervention_resources + ' action=' + $v.av_intervention_actions + ' at=' + $v.av_intervention_timestamps)
    Write-Host ('  timing      : scientific_runtime=' + $v.scientific_runtime_seconds + 's termination_overhead=' + $v.termination_overhead_seconds + 's telemetry_tail=' + $v.telemetry_tail_seconds + 's finalization_orchestration=' + $v.finalization_orchestration_seconds + 's')
    Write-Host ('  capture (D-156): window=' + $v.capture_window_seconds + 's post_workload=' + $v.post_workload_capture_seconds + 's stop_overhead=' + $v.capture_stop_overhead_seconds + 's closed_before_restore=' + $v.capture_closed_before_restore + ' lab_restore_inside_capture=' + $v.lab_restore_inside_capture)
    Write-Host ('  target (D-156): ' + $v.argument_vector_contract + ' -> ' + $v.resolved_argument_vector + '  mechanism=' + $v.target_mechanism)
    if (-not $v.ok) { exit 1 }
    exit 0
}

# ------------------------------------------------------------------ preconditions
$free = [math]::Round((Get-PSDrive -Name D).Free / 1GB, 2)
Assert-True (-not (Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_MUST_BE_OFF_PRE_PREFLIGHT'
Assert-True (-not (Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_MUST_BE_OFF_PRE_PREFLIGHT'
Assert-True ((Get-SnapshotName $WindowsVmxPath) -ceq $WindowsSnapshot) ('WINDOWS_CURRENT_SNAPSHOT_MISMATCH:' + (Get-SnapshotName $WindowsVmxPath))
Assert-True ((Get-SnapshotName $UbuntuVmxPath) -ceq $UbuntuSnapshot) ('UBUNTU_CURRENT_SNAPSHOT_MISMATCH:' + (Get-SnapshotName $UbuntuVmxPath))
Assert-True ($free -ge $MinFreeGiB) ('DISK_BELOW_MIN_FREE:' + $free)
$preBefore = @(Get-ChildItem -LiteralPath $PreflightRoot -Directory -ErrorAction SilentlyContinue).Count
Assert-True ($preBefore -eq 0) ('WINDOWS_PREFLIGHT_RUNS_NOT_EMPTY:' + $preBefore)
$offBefore = @(Get-ChildItem -LiteralPath $OfficialRoot -Directory -ErrorAction SilentlyContinue).Count
Assert-True ($offBefore -eq 0) ('WINDOWS_OFFICIAL_RUNS_NOT_EMPTY_AT_START:' + $offBefore)
Write-Host ('PREFLIGHT: preconditions PASS (D: free {0} GiB, both VMs off, Windows snapshot = V11, Ubuntu snapshot = V11, no Windows preflight or official run yet).' -f $free) -ForegroundColor Green

# ------------------------------------------------------------------ the runs
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$summaryJson = Join-Path $SummaryDir ('WINDOWS_10_FAMILY_PREFLIGHT_SUMMARY_' + $stamp + '.json')
$halted = $false
$haltReason = ''

foreach ($p in $Plan) {
    if ($MaxRuns -gt 0 -and $Script:Results.Count -ge $MaxRuns) { Write-Host 'PREFLIGHT: -MaxRuns reached; stopping.' -ForegroundColor Yellow; break }
    Write-Host ''
    Write-Host ('=' * 96) -ForegroundColor Cyan
    Write-Host ('PREFLIGHT {0}/10  {1}  {2}  (contract={3}, sample argv=NO_ARGUMENTS)' -f ($Script:Results.Count + 1), $p.run_id, $p.family, $p.invocation_mode) -ForegroundColor Cyan
    Write-Host ('=' * 96) -ForegroundColor Cyan

    $before = @(Get-ChildItem -LiteralPath $PreflightRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $cmd = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Controller,
        '-CampaignRoot', $CampaignRoot, '-RunMode', 'Preflight',
        '-VmrunPath', $VmrunPath, '-VMwareGuiPath', $VMwareGuiPath,
        '-WindowsVmxPath', $WindowsVmxPath, '-UbuntuVmxPath', $UbuntuVmxPath,
        '-WindowsSnapshot', $WindowsSnapshot, '-UbuntuSnapshot', $UbuntuSnapshot,
        '-RunID', $p.run_id, '-ExecutionOrder', ([string]$p.execution_order),
        '-SampleRunId', $p.sample_run_id, '-FamilyStratum', $p.family,
        '-Split', $p.split, '-Repetition', $p.repetition,
        '-ScenarioRunId', $p.scenario_run_id, '-FixtureSeed', $p.fixture_seed,
        '-SampleSha256', $p.sample_sha256, '-SampleBytes', $p.sample_bytes,
        '-SampleGuestPath', $p.sample_guest_path, '-ReadOnly', $p.read_only,
        '-ModeOctal', $p.mode_octal, '-GroundTruth', 'RANSOMWARE',
        '-ProcessDensityRole', 'MALICIOUS_PRIMARY_SUBJECT', '-EvidenceArchiveFormat', 'zip',
        '-TelemetryAdapter', 'Sysmon+Procmon', '-Status', $p.status
    )
    & powershell @cmd
    $rc = $LASTEXITCODE

    $after = @(Get-ChildItem -LiteralPath $PreflightRoot -Directory -ErrorAction SilentlyContinue)
    $new = @($after | Where-Object { $before -notcontains $_.Name })
    $runDir = if ($new.Count -eq 1) { $new[0].FullName } else { '' }

    $entry = [ordered]@{
        run_id = $p.run_id; execution_order = $p.execution_order; family = $p.family
        split = $p.split; repetition = $p.repetition
        invocation_contract = $p.invocation_contract; argv_actually_used = $p.argv_actually_used
        invocation_mode = $p.invocation_mode; invocation_image_type = $p.invocation_image_type
        invocation_loader_path = $p.invocation_loader_path; invocation_entry_point = $p.invocation_entry_point
        exit_code = $rc; evidence_package = $runDir; status = 'FAIL'; failure = ''
        official_slots_consumed = 0; termination_mode = ''; sample_exit_code = ''
        watchdog_fired = $false; watchdog_armed = $false; actual_execution_seconds = ''; canary_total = ''
        canaries_modified = ''; canary_all_intact = ''; telemetry_rows = ''
        canaries_missing = ''; canaries_hash_mismatched = ''
        sample_exit_code_class = ''; sample_runtime_seconds = ''; kill_settle_seconds = ''
        av_interference_mitigated = ''; antivirus_summary = ''; antivirus_detections = ''
        antivirus_remediated = ''; antivirus_behavioural = ''; antivirus_remediated_other = ''
        antivirus_threat_names = ''
        av_intervened = ''; av_status_class = ''; av_intervention = ''
        av_intervention_threats = ''; av_intervention_resources = ''
        av_intervention_actions = ''; av_intervention_timestamps = ''
        scientific_runtime_seconds = ''; termination_overhead_seconds = ''
        telemetry_tail_seconds = ''; finalization_orchestration_seconds = ''
        # D-156: the capture-boundary semantics.
        post_workload_capture_seconds = ''; capture_stop_overhead_seconds = ''; capture_window_seconds = ''
        capture_start_utc = ''; capture_stop_utc = ''; capture_closed_before_restore = ''
        lab_restore_inside_capture = ''; telemetry_restore_seconds = ''; lab_restore_seconds = ''
        argument_vector_contract = ''; resolved_argument_vector = ''; target_mechanism = ''
        documented_scope_evidence = ''; expected_canary_effect = ''
    }

    if ($rc -ne 0) {
        $entry.failure = 'CONTROLLER_EXIT_' + $rc
        $Script:Results += [pscustomobject]$entry
        $halted = $true; $haltReason = $p.run_id + ': controller exit ' + $rc
        Write-Host ('PREFLIGHT HALT: ' + $p.run_id + ' failed (controller exit ' + $rc + '). Evidence: ' + $runDir) -ForegroundColor Red
        break
    }

    # D-135: the verification is the shared function, so it is the SAME code that -VerifyPackage
    # exercises against a real package without executing anything.
    # D-166: [bool]::TryParse RETURNS the parse result, NOT the parsed value - the previous code
    # assigned the parse result, forcing watchdog_fired=true for every parseable field. The parsed
    # value ($wf / $wa) is now assigned; the schema separates armed from fired. (The FAIL-armament
    # empty-string guard is retained by the else branches.)
    $verdict = Test-RunEvidence -RunDir $runDir -ExpectedInvocationMode $p.invocation_mode -ExpectedArgumentVector $p.argument_vector_template
    $wf = $false
    $wa = $false
    $slots = 0
    $parsed = 0.0
    $entry.termination_mode = $verdict.termination_mode
    if ([bool]::TryParse([string]$verdict.watchdog_armed, [ref]$wa)) { $entry.watchdog_armed = $wa } else { $entry.watchdog_armed = $false }
    if ([bool]::TryParse([string]$verdict.watchdog_fired, [ref]$wf)) { $entry.watchdog_fired = $wf } else { $entry.watchdog_fired = $false }
    if ([double]::TryParse([string]$verdict.official_slots_consumed, [ref]$parsed)) { $slots = [int]$parsed }
    $entry.official_slots_consumed = $slots
    $entry.sample_exit_code = [string]$verdict.sample_exit_code
    $entry.sample_exit_code_class = [string]$verdict.sample_exit_code_class
    $entry.actual_execution_seconds = [string]$verdict.actual_execution_seconds
    $entry.sample_runtime_seconds = [string]$verdict.sample_runtime_seconds
    $entry.kill_settle_seconds = [string]$verdict.kill_settle_seconds
    $entry.canary_total = $verdict.canary_total
    $entry.canaries_modified = $verdict.canaries_modified
    $entry.canary_all_intact = $verdict.canary_all_intact
    $entry.canaries_missing = $verdict.canaries_missing
    $entry.canaries_hash_mismatched = $verdict.canaries_hash_mismatched
    $entry.canary_root = $verdict.canary_root
    $entry.telemetry_rows = $verdict.telemetry_rows
    $entry.av_interference_mitigated = $verdict.av_interference_mitigated
    $entry.antivirus_summary = $verdict.antivirus_summary
    $entry.antivirus_detections = $verdict.antivirus_detections
    $entry.antivirus_remediated = $verdict.antivirus_remediated
    $entry.antivirus_behavioural = $verdict.antivirus_behavioural
    $entry.antivirus_remediated_other = $verdict.antivirus_remediated_other
    $entry.antivirus_threat_names = $verdict.antivirus_threat_names
    # D-147: the AV characterisation and the four explicit timing semantics.
    $entry.av_intervened = $verdict.av_intervened
    $entry.av_status_class = $verdict.av_status_class
    $entry.av_intervention = $verdict.av_intervention
    $entry.av_intervention_threats = $verdict.av_intervention_threats
    $entry.av_intervention_resources = $verdict.av_intervention_resources
    $entry.av_intervention_actions = $verdict.av_intervention_actions
    $entry.av_intervention_timestamps = $verdict.av_intervention_timestamps
    $entry.scientific_runtime_seconds = $verdict.scientific_runtime_seconds
    $entry.termination_overhead_seconds = $verdict.termination_overhead_seconds
    $entry.telemetry_tail_seconds = $verdict.telemetry_tail_seconds
    $entry.finalization_orchestration_seconds = $verdict.finalization_orchestration_seconds
    # D-156: the capture-boundary values and the frozen target contract.
    $entry.post_workload_capture_seconds = $verdict.post_workload_capture_seconds
    $entry.capture_stop_overhead_seconds = $verdict.capture_stop_overhead_seconds
    $entry.capture_window_seconds = $verdict.capture_window_seconds
    $entry.capture_start_utc = $verdict.capture_start_utc
    $entry.capture_stop_utc = $verdict.capture_stop_utc
    $entry.capture_closed_before_restore = $verdict.capture_closed_before_restore
    $entry.lab_restore_inside_capture = $verdict.lab_restore_inside_capture
    $entry.telemetry_restore_seconds = $verdict.telemetry_restore_seconds
    $entry.lab_restore_seconds = $verdict.lab_restore_seconds
    $entry.argument_vector_contract = $verdict.argument_vector_contract
    $entry.resolved_argument_vector = $verdict.resolved_argument_vector
    $entry.target_mechanism = $verdict.target_mechanism
    $entry.documented_scope_evidence = [string]$p.target_evidence
    $entry.expected_canary_effect = [string]$p.target_expected_effect
    $entry.invocation_mode = $verdict.invocation_mode
    $entry.invocation_entry_point = $verdict.invocation_entry_point
    $entry.invocation_loader_path = $verdict.invocation_loader_path
    $entry.sample_arguments = $verdict.sample_arguments
    $entry.sample_image_dll = $verdict.sample_image_dll
    $fail = $verdict.failure
    if ($fail -ne '') { $fail = [string]$fail }

    # D-134: the WINDOWS receipt shapes. The canary receipt uses canary_total / canary_mismatches
    # (an array) and the telemetry receipt has NO row count - the raw capture is a Procmon PML
    # plus a Sysmon process-tree CSV, with an event-loss counter.


    $preAfter = @(Get-ChildItem -LiteralPath $PreflightRoot -Directory -ErrorAction SilentlyContinue).Count
    # D-135: the count check only speaks when no failure has been recorded, so the real
    # failure code is never overwritten by the secondary one.
    if (($fail -eq '' -or $null -eq $fail) -and ($preAfter -ne ($before.Count + 1))) { $fail = 'PREFLIGHT_PACKAGE_COUNT_NOT_PLUS_ONE' }

    if ($fail) {
        $entry.failure = $fail
        $Script:Results += [pscustomobject]$entry
        $halted = $true; $haltReason = $p.run_id + ': ' + $fail
        Write-Host ('PREFLIGHT HALT: ' + $p.run_id + ' -> ' + $fail + '. Evidence: ' + $runDir) -ForegroundColor Red
        break
    }
    # D-147: an AV intervention is a CHARACTERISATION OUTCOME - the run is NOT a clean PASS,
    # and the series CONTINUES to the next family.
    $statusClass = [string]$verdict.av_status_class
    if ($statusClass -eq 'CHARACTERIZED_WITH_AV_INTERVENTION') {
        $entry.status = 'CHARACTERIZED_WITH_AV_INTERVENTION'
        $Script:Results += [pscustomobject]$entry
        Write-Host ('PREFLIGHT CHARACTERIZED_WITH_AV_INTERVENTION: ' + $p.run_id + '  slots=0  termination=' + $entry.termination_mode + '  exit=' + $entry.sample_exit_code + '/' + $entry.sample_exit_code_class + '  scientific_runtime=' + $entry.scientific_runtime_seconds + 's  termination_overhead=' + $entry.termination_overhead_seconds + 's  canaries=' + $entry.canaries_modified + '/' + $entry.canary_total) -ForegroundColor Yellow
        Write-Host ('   AV: av_intervened=' + $entry.av_intervened + ' threat=' + $entry.av_intervention_threats + ' | resource=' + $entry.av_intervention_resources + ' | action=' + $entry.av_intervention_actions + ' | at=' + $entry.av_intervention_timestamps) -ForegroundColor Yellow
        Write-Host ('   the frozen AV policy is unchanged (analysis exclusions, Defender NOT globally disabled); the official Windows runs remain FAIL-CLOSED on any AV intervention') -ForegroundColor Yellow
        Write-Host ('   evidence: ' + $runDir) -ForegroundColor DarkGray
        continue
    }
    $entry.status = 'PASS'
    $Script:Results += [pscustomobject]$entry
    Write-Host ('PREFLIGHT PASS: ' + $p.run_id + '  slots=0  termination=' + $entry.termination_mode + '  exit=' + $entry.sample_exit_code + '/' + $entry.sample_exit_code_class + '  scientific_runtime=' + $entry.scientific_runtime_seconds + 's  termination_overhead=' + $entry.termination_overhead_seconds + 's  capture_window=' + $entry.capture_window_seconds + 's  post_workload_capture=' + $entry.post_workload_capture_seconds + 's  telemetry_tail=' + $entry.telemetry_tail_seconds + 's  finalization_orchestration=' + $entry.finalization_orchestration_seconds + 's  canaries=' + $entry.canaries_modified + '/' + $entry.canary_total + '  ' + $entry.telemetry_rows + '  av_intervened=' + $entry.av_intervened + '  argv=' + $entry.argument_vector_contract) -ForegroundColor Green
    Write-Host ('   evidence: ' + $runDir) -ForegroundColor DarkGray
}

# ------------------------------------------------------------------ the summary
$passed = @($Script:Results | Where-Object { $_.status -ceq 'PASS' }).Count
# D-147: an AV-characterised family is COMPLETE (measured) but is NOT a clean PASS.
$characterized = @($Script:Results | Where-Object { $_.status -ceq 'CHARACTERIZED_WITH_AV_INTERVENTION' }).Count
$failed = @($Script:Results | Where-Object { $_.status -ne 'PASS' -and $_.status -ne 'CHARACTERIZED_WITH_AV_INTERVENTION' }).Count
$attempted = $Script:Results.Count
$seriesComplete = (-not $halted) -and ($attempted -eq 10) -and ($failed -eq 0)
$summary = [ordered]@{
    schema_version = '1.1'
    gate = 'WINDOWS_10_FAMILY_PREFLIGHT'
    generated_utc = [DateTime]::UtcNow.ToString('o')
    status = if ($halted) { 'FAIL' } elseif ($seriesComplete) { $(if ($characterized -gt 0) { 'PASS_WITH_AV_CHARACTERIZATIONS' } else { 'PASS' }) } else { 'INCOMPLETE' }
    families_planned = $Plan.Count
    families_attempted = $attempted
    families_passed = $passed
    families_characterized_with_av_intervention = $characterized
    families_failed = $failed
    av_characterization_policy = 'D-147 PREFLIGHT ONLY: an AV intervention is recorded as a characterisation outcome (av_intervened=true, threat/resource/action/timestamp) with status CHARACTERIZED_WITH_AV_INTERVENTION; it is never a clean PASS and it never halts the series. The OFFICIAL Windows runs remain FAIL-CLOSED.'
    official_runs_authorized = $false
    halt_reason = $haltReason
    official_campaign_slots_consumed = 0
    windows_baseline = $WindowsSnapshot
    ubuntu_baseline = $UbuntuSnapshot
    canary_corpus = 'FROZEN 236-file common corpus (Corpus V2)'
    invocation_contract_status = 'FROZEN PER SAMPLE (D-153): 01_SHARED\manifests\WINDOWS_INVOCATION_CONTRACTS.csv. Nine families are EXE images launched directly with NO_ARGUMENTS; WannaCry (W-R-07) is a PE32+ DLL (IMAGE_FILE_DLL) and is loaded by rundll32.exe with the export PlayGame. The sample, hash, timing, telemetry and AV policy are unchanged; the argv actually used is recorded per run.'
    results = $Script:Results
}
Write-Json $summaryJson $summary
Write-Host ''
Write-Host ('WINDOWS PREFLIGHT SUMMARY: ' + $passed + '/10 clean PASS, ' + $characterized + '/10 CHARACTERIZED_WITH_AV_INTERVENTION, ' + $failed + ' failed; official slots consumed=0; summary: ' + $summaryJson) -ForegroundColor $(if ($halted -or $failed -gt 0) { 'Red' } else { 'Green' })
if ($halted) { Write-Host ('HALTED: ' + $haltReason + ' - the remaining families were not attempted.') -ForegroundColor Red; exit 1 }
if ($failed -gt 0 -or $attempted -ne 10) { Write-Host ('INCOMPLETE: ' + $attempted + '/10 families attempted, ' + $failed + ' hard failure(s).') -ForegroundColor Red; exit 1 }
if ($characterized -gt 0) {
    Write-Host ('ALL TEN WINDOWS FAMILIES CHARACTERISED: ' + $passed + ' clean PASS, ' + $characterized + ' CHARACTERIZED_WITH_AV_INTERVENTION.') -ForegroundColor Yellow
    Write-Host 'The official Windows runs remain UNAUTHORISED by this script; an AV-remediated family is NOT authorised for official execution merely because the preflight continued.' -ForegroundColor Yellow
} else {
    Write-Host 'ALL TEN WINDOWS PREFLIGHTS PASSED. The official Windows runs may now be authorised by the owner (still NOT authorised by this script).' -ForegroundColor Green
}
exit 0
