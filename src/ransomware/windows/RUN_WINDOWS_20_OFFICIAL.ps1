<#
    RUN_WINDOWS_20_OFFICIAL.ps1
    ===========================
    The OFFICIAL Windows ransomware campaign block: 20 official runs = the 10 qualified
    families x 2 repetitions, executed ONE AT A TIME, sequentially, in campaign execution
    order (1..20).

    AUTHORISATION: the owner authorised the official 20 Windows ransomware runs on
    2026-11-15 (console instruction; recorded in DECISIONS.md D-167), on the condition
    that the fresh 10-family Windows preflight had passed 10/10 - it did (D-166;
    WINDOWS_10_FAMILY_PREFLIGHT_SUMMARY_20261115_195554.json, status PASS, 10/10,
    0 slots).

    WHAT THIS SCRIPT DOES
      * drives the FROZEN production Windows controller (RANSOMWARE_Official_Run_Controller.ps1)
        with RunMode=Official, once per manifest row, in a SEPARATE child process so each
        run is a complete, independent cycle: boot from the frozen V11 baseline -> stage the
        sample and the frozen 236-file canary corpus -> Sysmon+Procmon telemetry -> execute
        the sample under the family's FROZEN invocation contract under a 60 s bounded
        observation with the 90 s watchdog -> canary integrity -> evidence pack -> power off
        -> revert to V11 -> restore the host network;
      * NEVER runs two runs at once and NEVER reuses a guest session - each run is its own
        boot/revert cycle, so a run cannot contaminate the next;
      * HALTS ON THE FIRST FAILURE: the failing run's evidence package is kept, no further
        run is attempted, and the remaining slots stay unconsumed;
      * verifies EVERY run's evidence before starting the next one (status, mode, slot
        count, the argv against the frozen contract, the 236-file corpus, the recovery to
        V11, the capture archive) and asserts that the official-run directory grew by
        exactly one package per successful run.

    SLOT ACCOUNTING
      RunMode=Official consumes exactly ONE of the 40 official campaign slots per
      SUCCESSFUL run (the controller writes official_campaign_slots_consumed=1); a failed
      run consumes none. The Ubuntu official block consumed 20; this script consumes at
      most the remaining 20. This script records the per-run and the total in its summary.

    THE MANIFESTS ARE NOT MODIFIED BY THIS SCRIPT. The manifest's status column stays
    PENDING (the authoritative outcome of each run lives in its evidence package and in
    this script's summary), because the manifests are frozen.

    Usage:
      powershell -NoProfile -ExecutionPolicy Bypass -File RUN_WINDOWS_20_OFFICIAL.ps1
      powershell -NoProfile -ExecutionPolicy Bypass -File RUN_WINDOWS_20_OFFICIAL.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [string]$CampaignRoot = 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs',
    [int]$MaxRuns = 0,
    [switch]$DryRun,
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
$InvocationContracts = Join-Path $CampaignRoot '01_SHARED\manifests\WINDOWS_INVOCATION_CONTRACTS.csv'
$TargetContracts = Join-Path $CampaignRoot '01_SHARED\manifests\WINDOWS_FAMILY_TARGET_CONTRACTS.csv'
$V11Manifest = Join-Path $CampaignRoot '01_SHARED\scripts\host\sample_selection\WINDOWS_V11_EXPECTED_SHA256.tsv'
$OfficialRoot = Join-Path $CampaignRoot '04_WINDOWS\RANSOMWARE\official_runs'
$PreflightRoot = Join-Path $CampaignRoot '04_WINDOWS\RANSOMWARE\preflight_runs'
$ResultsRoot = Join-Path $CampaignRoot '04_WINDOWS\RANSOMWARE\results'
$SummaryDir = Join-Path $CampaignRoot '01_SHARED\audit\WINDOWS_10_FAMILY_PREFLIGHT_20261112'

# every input is pinned; if any of them moved the campaign does not start
$Pinned = [ordered]@{
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RANSOMWARE_Official_Run_Controller.ps1' = 'a192a1de1f8a025a1872a8387647fce176afa2ce643396606c0d9df5aec4ffe8'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RANSOMWARE_Guest_Execute_Official.ps1' = '5fb5f0a51313ea2e413331e264f9227bfcd7e751a74ee07ded78831eea121732'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RANSOMWARE_Guest_Telemetry.ps1'     = '5358cf32f273c58340d0096edaaad8ebcef37e7c0265bed92a644fe0bffbfd1c'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RANSOMWARE_Guest_Pack.ps1'           = '1273f9dcaf0442befb141cce032a0684f5f097ef1ab1e2b5beca7e48b0b8eaed'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\HCQNativeBridge.ps1'                = '312d8ef5a6376925b7b60c82722802ec50aecbc0c571029e1978cbc6fd55e33d'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\NetworkBaseline.ps1'               = 'd37f4a06d511f046cec0ea5dd98e496a66dc9f61343d6fd108658d2988a60e1e'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\RANSOMWARE_Guest_Antivirus.ps1'     = '2991e3b8d2edcf3ae602cfbb71326b488bf2f90990947468cd30e3a592b9cbea'
    '01_SHARED\manifests\RANSOMWARE_40_RUN_MANIFEST.csv'                                                  = 'ed97c399ff87e19ecc1d8761ba8a20d7ac44cbf7b7fdfd80a4fcd7ff545d870d'
    '01_SHARED\manifests\CAMPAIGN_100_RUN_MANIFEST.csv'                                                   = '3f9d8ad577af830a87d23486341fb728b06a80902cb3fed2f7f8dd42c64fc843'
    '01_SHARED\manifests\WINDOWS_INVOCATION_CONTRACTS.csv'                                                = '2c52f9d78f6c625c3acfe57c9a901f09ba9112ef6a461d9a8c6f6b5692e48636'
    '01_SHARED\manifests\WINDOWS_FAMILY_TARGET_CONTRACTS.csv'                                             = '7c6a9e0704442ac12e3cd596b9fce07a5b95432a80281482f07f967f6b5ee056'
    '01_SHARED\scripts\host\sample_selection\WINDOWS_V11_EXPECTED_SHA256.tsv'                            = 'd57a1af2942ff0317493b707079f33465ef41d802073c6f53d57eb3d1a01a223'
}

$Script:Results = @()

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw ('OFFICIAL_RUN_FAILURE:' + $Message) } }
function SHA([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-Json([string]$Path, [object]$Object) {
    $d = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    [IO.File]::WriteAllText($Path, (($Object | ConvertTo-Json -Depth 20) + "`r`n"), (New-Object Text.UTF8Encoding($false)))
}
function Get-VmOn([string]$Vmrun, [string]$Vmx) {
    $out = & $Vmrun list 2>$null
    return (@($out | Where-Object { $_ -and ([string]$_).Trim().ToLowerInvariant() -eq $Vmx.ToLowerInvariant() }).Count -gt 0)
}
function Get-CurrentSnapshotName([string]$Vmx) {
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
Write-Host 'OFFICIAL: every pinned input matches its recorded hash.' -ForegroundColor Green

# ------------------------------------------------------------------ the plan (20 runs = 10 families x 2 repetitions)
$Rows40 = @(Import-Csv -LiteralPath $Manifest40)
$Rows100 = @(Import-Csv -LiteralPath $Manifest100)
# D-153: the frozen per-sample invocation contract. Nine of the ten Windows families are ordinary
# EXE images and keep the original NO_ARGUMENTS launch. WannaCry (W-R-07) is a PE32+ DLL with the
# single export PlayGame - loaded through rundll32.exe. The contract is per-SAMPLE (keyed by
# sample_sha256), so both repetitions of a family share it; it is bound by hash, never by name.
$ContractRows = @(Import-Csv -LiteralPath $InvocationContracts)
Assert-True ($ContractRows.Count -eq 20) ('INVOCATION_CONTRACT_ROW_COUNT:' + $ContractRows.Count)
# D-156: the frozen target contract. Bound by sample hash as well, closed vector set.
$TargetRows = @(Import-Csv -LiteralPath $TargetContracts)
Assert-True ($TargetRows.Count -eq 20) ('TARGET_CONTRACT_ROW_COUNT:' + $TargetRows.Count)
$Plan = @()
foreach ($r in @($Rows40 | Where-Object { $_.platform -ceq 'Windows' } | Sort-Object { [int]$_.execution_order })) {
    Assert-True ([string]$r.snapshot_baseline -ceq $WindowsSnapshot) ('WINDOWS_ROW_BASELINE_NOT_V11:' + $r.run_id)
    $c = @($Rows100 | Where-Object { $_.run_id -ceq $r.run_id })
    Assert-True ($c.Count -eq 1) ('CAMPAIGN_ROW_NOT_FOUND:' + $r.run_id)
    Assert-True ([string]$c[0].snapshot_baseline -ceq $WindowsSnapshot) ('CAMPAIGN_ROW_BASELINE_NOT_V11:' + $r.run_id)
    # D-153: bind the invocation contract row by SAMPLE HASH; fail-closed.
    $ct = @($ContractRows | Where-Object { $_.run_id -ceq $r.run_id -and $_.sample_sha256 -ceq $r.sample_sha256 -and $_.family_stratum -ceq $r.family_stratum })
    Assert-True ($ct.Count -eq 1) ('INVOCATION_CONTRACT_NOT_FOUND:' + $r.run_id)
    $ct = $ct[0]
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
    # D-156: bind the frozen TARGET contract row by SAMPLE HASH; fail-closed. Closed vector set.
    $tg = @($TargetRows | Where-Object { $_.run_id -ceq $r.run_id -and $_.sample_sha256 -ceq $r.sample_sha256 -and $_.family_stratum -ceq $r.family_stratum })
    Assert-True ($tg.Count -eq 1) ('TARGET_CONTRACT_NOT_FOUND:' + $r.run_id)
    $tg = $tg[0]
    Assert-True ([string]$tg.invocation_mode -ceq [string]$ct.invocation_mode) ('TARGET_CONTRACT_INVOCATION_MODE_MISMATCH:' + $r.run_id)
    Assert-True ([string]$tg.loader_path -ceq [string]$ct.loader_path) ('TARGET_CONTRACT_LOADER_MISMATCH:' + $r.run_id)
    Assert-True ([string]$tg.entry_point -ceq [string]$ct.entry_point) ('TARGET_CONTRACT_ENTRY_MISMATCH:' + $r.run_id)
    $vec = [string]$tg.argument_vector_template
    Assert-True ($vec -match '^(NO_ARGUMENTS|--[a-z0-9_]+ <CANARY>)$') ('TARGET_CONTRACT_ARGUMENT_VECTOR_NOT_CLOSED:' + $r.run_id + ':' + $vec)
    $expectedTokens = $(if ($vec -ceq 'NO_ARGUMENTS') { 0 } else { 2 })
    Assert-True ([int]$tg.argument_tokens -eq $expectedTokens) ('TARGET_CONTRACT_ARGUMENT_TOKEN_COUNT:' + $r.run_id)
    Assert-True ([string]$tg.target_mechanism -in @('EXPLICIT_DOCUMENTED_SWITCH','DOCUMENTED_SCOPE_NO_EXPLICIT_TARGET','NO_ENCRYPTION_TARGET')) ('TARGET_CONTRACT_MECHANISM_UNKNOWN:' + $r.run_id)
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$tg.documented_scope_evidence)) ('TARGET_CONTRACT_EVIDENCE_MISSING:' + $r.run_id)
    # D-163/D-164: the V11 expected-SHA set must contain this exact build (column 0 = sha256).
    $v11 = @(Get-Content -LiteralPath $V11Manifest -ErrorAction Stop | Where-Object { $_ -and ($_ -notmatch '^#') } | ForEach-Object { ($_ -split "`t")[0] })
    Assert-True ($v11 -contains [string]$r.sample_sha256) ('EXPECTED_SHA256_MANIFEST_MISSING_ROW:' + $r.run_id)
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
        # D-133: Windows has no POSIX mode; the manifest's mode_octal column is empty for Windows.
        mode_octal = 'N/A'
        read_only = 'True'
        status = 'PENDING'
        invocation_contract = 'FROZEN_PER_SAMPLE:' + [string]$ct.invocation_mode
        invocation_mode = [string]$ct.invocation_mode
        invocation_image_type = [string]$ct.image_type
        invocation_loader_path = [string]$ct.loader_path
        invocation_entry_point = [string]$ct.entry_point
        contract = $vec
        target_mechanism = [string]$tg.target_mechanism
    }
}
Assert-True ($Plan.Count -eq 20) ('PLAN_RUN_COUNT_NOT_20:' + $Plan.Count)
Assert-True ((@($Plan.run_id | Sort-Object -Unique).Count) -eq 20) 'PLAN_DUPLICATE_RUN_ID'
Assert-True ((@($Plan.execution_order | Sort-Object -Unique).Count) -eq 20) 'PLAN_DUPLICATE_EXECUTION_ORDER'
Assert-True ((@($Plan.family | Sort-Object -Unique).Count) -eq 10) 'PLAN_FAMILY_COUNT_NOT_10'
# exactly one DLL-loading family exists, and it is WannaCry (W-R-07), both repetitions.
$LoaderPlans = @($Plan | Where-Object { $_.invocation_mode -ceq 'RUNDLL32_EXPORT' })
Assert-True ($LoaderPlans.Count -eq 2) ('INVOCATION_CONTRACT_LOADER_PLAN_COUNT:' + $LoaderPlans.Count)
Assert-True ((@($LoaderPlans | Where-Object { $_.sample_run_id -ceq 'W-R-07' -and $_.family -ceq 'WannaCry' -and $_.invocation_entry_point -ceq 'PlayGame' }).Count) -eq 2) 'INVOCATION_CONTRACT_LOADER_PLAN_ENTRY'
Assert-True ((@($Plan | Where-Object { $_.invocation_mode -ceq 'DIRECT_EXE' }).Count) -eq 18) 'INVOCATION_CONTRACT_DIRECT_PLAN_COUNT'

Write-Host ''
Write-Host ('=== OFFICIAL WINDOWS CAMPAIGN BLOCK: 20 runs = 10 families x 2 repetitions ===') -ForegroundColor Cyan
Write-Host ('{0,-5} {1,-15} {2,-13} {3,-11} {4,-6} {5,-40} {6}' -f 'ord', 'run_id', 'family', 'split', 'rep', 'frozen target contract', 'fixture seed')
foreach ($p in $Plan) {
    Write-Host ('{0,-5} {1,-15} {2,-13} {3,-11} {4,-6} {5,-40} {6}' -f $p.execution_order, $p.run_id, $p.family, $p.split, $p.repetition, $p.contract, $p.fixture_seed)
}
Write-Host ''

if ($DryRun) { Write-Host 'DRY RUN: nothing was executed; no slot was consumed.' -ForegroundColor Yellow; exit 0 }

# ------------------------------------------------------------------ preconditions
$free = [math]::Round((Get-PSDrive -Name D).Free / 1GB, 2)
Assert-True (-not (Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_MUST_BE_OFF_PRE_RUN'
Assert-True (-not (Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_MUST_BE_OFF_PRE_RUN'
Assert-True ((Get-CurrentSnapshotName $WindowsVmxPath) -ceq $WindowsSnapshot) ('WINDOWS_CURRENT_SNAPSHOT_NOT_V11:' + (Get-CurrentSnapshotName $WindowsVmxPath))
Assert-True ((Get-CurrentSnapshotName $UbuntuVmxPath) -ceq $UbuntuSnapshot) ('UBUNTU_CURRENT_SNAPSHOT_NOT_V11:' + (Get-CurrentSnapshotName $UbuntuVmxPath))
Assert-True ($free -ge $MinFreeGiB) ('DISK_BELOW_MIN_FREE:' + $free)
$officialBefore = @(Get-ChildItem -LiteralPath $OfficialRoot -Directory -ErrorAction SilentlyContinue).Count
Assert-True ($officialBefore -eq 0) ('OFFICIAL_RUNS_NOT_EMPTY_AT_START:' + $officialBefore)
# D-166/D-167: the fresh 10-family Windows preflight must exist and must be the accepted 10/10 PASS.
$preSummary = @(Get-ChildItem -LiteralPath $SummaryDir -Filter 'WINDOWS_10_FAMILY_PREFLIGHT_SUMMARY_*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1)
Assert-True ($preSummary.Count -eq 1) 'PREFLIGHT_SUMMARY_MISSING'
$pre = Get-Content -LiteralPath $preSummary[0].FullName -Raw | ConvertFrom-Json
Assert-True ([string]$pre.status -ceq 'PASS' -and [int]$pre.families_passed -eq 10 -and [int]$pre.families_failed -eq 0) 'PREFLIGHT_SERIES_NOT_PASS_10_OF_10'
Assert-True ([int]$pre.official_campaign_slots_consumed -eq 0) 'PREFLIGHT_CONSUMED_SLOTS'
$preflightPkgs = @(Get-ChildItem -LiteralPath $PreflightRoot -Directory -Filter 'RAN_WIN_*' -ErrorAction SilentlyContinue).Count
Assert-True ($preflightPkgs -eq 10) ('PREFLIGHT_SERIES_INCOMPLETE:' + $preflightPkgs + ' of 10')
foreach ($p in Get-ChildItem -LiteralPath $PreflightRoot -Directory -Filter 'RAN_WIN_*' -ErrorAction SilentlyContinue) {
    $fv = Join-Path $p.FullName 'RUN_FULL_VERIFICATION.json'
    $rr = Join-Path $p.FullName 'RUN_RESULT.json'
    Assert-True (Test-Path -LiteralPath $fv -PathType Leaf) ('PREFLIGHT_PACKAGE_UNVERIFIED:' + $p.Name)
    $f = Get-Content -LiteralPath $fv -Raw -Encoding UTF8 | ConvertFrom-Json
    $r = Get-Content -LiteralPath $rr -Raw | ConvertFrom-Json
    Assert-True ([string]$f.status -ceq 'PASS' -and [int]$f.fail -eq 0) ('PREFLIGHT_PACKAGE_NOT_SELF_VERIFYING:' + $p.Name)
    Assert-True ([string]$r.status -ceq 'PASS') ('PREFLIGHT_PACKAGE_RUN_RESULT_NOT_PASS:' + $p.Name)
}
Write-Host ('OFFICIAL: preconditions PASS (D: free {0} GiB, both VMs off, Windows snapshot = V11, Ubuntu snapshot = V11, official_runs empty, accepted preflight 10/10 PASS on disk).' -f $free) -ForegroundColor Green

# ------------------------------------------------------------------ the runs
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$summaryJson = Join-Path $ResultsRoot ('OFFICIAL_WINDOWS_20_SUMMARY_' + $stamp + '.json')
$slots = 0
$halted = $false
$haltReason = ''

foreach ($p in $Plan) {
    if ($MaxRuns -gt 0 -and $Script:Results.Count -ge $MaxRuns) { Write-Host 'OFFICIAL: -MaxRuns reached; stopping.' -ForegroundColor Yellow; break }
    Write-Host ''
    Write-Host ('=' * 96) -ForegroundColor Cyan
    Write-Host ('OFFICIAL RUN {0}/20  {1}  {2}  contract: {3}' -f ($Script:Results.Count + 1), $p.run_id, $p.family, $p.contract) -ForegroundColor Cyan
    Write-Host ('=' * 96) -ForegroundColor Cyan

    $before = @(Get-ChildItem -LiteralPath $OfficialRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $cmd = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Controller,
        '-CampaignRoot', $CampaignRoot, '-RunMode', 'Official',
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

    $after = @(Get-ChildItem -LiteralPath $OfficialRoot -Directory -ErrorAction SilentlyContinue)
    $new = @($after | Where-Object { $before -notcontains $_.Name })
    $runDir = if ($new.Count -eq 1) { $new[0].FullName } else { '' }

    $entry = [ordered]@{
        run_id = $p.run_id; execution_order = $p.execution_order; family = $p.family
        split = $p.split; repetition = $p.repetition; frozen_contract = $p.contract
        invocation_mode = $p.invocation_mode
        exit_code = $rc; evidence_package = $runDir; status = 'FAIL'; failure = ''
        official_slots_consumed = 0; argv_used = ''; termination_mode = ''
        watchdog_fired = $false; canaries_modified = ''; canary_total = ''; telemetry_rows = ''
        sample_exit_code = ''; actual_execution_seconds = ''
    }

    if ($rc -ne 0) {
        $entry.failure = 'CONTROLLER_EXIT_' + $rc
        $Script:Results += [pscustomobject]$entry
        $halted = $true; $haltReason = $p.run_id + ': controller exit ' + $rc
        Write-Host ('OFFICIAL HALT: ' + $p.run_id + ' failed (controller exit ' + $rc + '). Evidence: ' + $runDir) -ForegroundColor Red
        break
    }

    $rr = Get-Content -LiteralPath (Join-Path $runDir 'RUN_RESULT.json') -Raw | ConvertFrom-Json
    $entry.official_slots_consumed = [int]$rr.official_campaign_slots_consumed
    $entry.termination_mode = [string]$rr.termination_mode
    $entry.watchdog_fired = [bool]$rr.watchdog_fired
    $entry.sample_exit_code = [int]$rr.exit_code
    $entry.actual_execution_seconds = [double]$rr.actual_execution_seconds
    $fail = $null
    if ([string]$rr.status -cne 'PASS') { $fail = 'RUN_RESULT_NOT_PASS' }
    if ([string]$rr.run_mode -cne 'Official') { $fail = 'RUN_MODE_NOT_OFFICIAL' }
    if (-not [bool]$rr.official_run) { $fail = 'OFFICIAL_RUN_FLAG_NOT_SET' }
    if ([bool]$rr.qualification_only) { $fail = 'OFFICIAL_RUNS_MARKED_AS_QUALIFICATION' }
    if ([int]$rr.official_campaign_slots_consumed -ne 1) { $fail = 'SLOT_COUNT_NOT_ONE' }
    if ([int]$rr.execution_order -ne $p.execution_order) { $fail = 'EXECUTION_ORDER_MISMATCH' }
    if ([string]$rr.family_stratum -cne $p.family) { $fail = 'FAMILY_MISMATCH' }
    if (-not [bool]$rr.watchdog_armed) { $fail = 'WATCHDOG_NOT_ARMED' }
    if (-not [bool]$rr.recovery_verified) { $fail = 'RECOVERY_NOT_VERIFIED' }

    $sx = Get-Content -LiteralPath (Join-Path $runDir 'evidence\sample_execute_receipt.json') -Raw | ConvertFrom-Json
    $pr = Get-Content -LiteralPath (Join-Path $runDir 'evidence\sample_prepare_receipt.json') -Raw | ConvertFrom-Json
    $ci = Get-Content -LiteralPath (Join-Path $runDir 'evidence\canary_integrity_receipt.json') -Raw | ConvertFrom-Json
    $tc = Get-Content -LiteralPath (Join-Path $runDir 'evidence\telemetry_capture_receipt.json') -Raw | ConvertFrom-Json
    $rcv = Get-Content -LiteralPath (Join-Path $runDir 'recovery\POST_RECOVERY_VERIFICATION.json') -Raw | ConvertFrom-Json
    $entry.argv_used = [string]$sx.sample_arguments
    $entry.canaries_modified = [string]@(@($ci.canary_mismatches) | Where-Object { $null -ne $_ }).Count
    $entry.canary_total = [string]$ci.canary_total
    $entry.telemetry_rows = ('pml_bytes=' + [string]$tc.capture_pml_bytes + '; sysmon_tree_csv_bytes=' + [string]$tc.sysmon_process_tree_csv_bytes + '; event_loss=' + [string]$tc.event_loss_count)

    $expectedArgv = ($p.contract -replace '<CANARY>', [string]$pr.canary_root)
    if ([string]$sx.sample_arguments -cne $expectedArgv) { $fail = 'ARGV_NOT_THE_FROZEN_CONTRACT' }
    if ([int]$pr.canary_count -ne 236) { $fail = 'CANARY_COUNT_NOT_236' }
    if ([string]$pr.status -cne 'PASS') { $fail = 'SAMPLE_PREPARE_NOT_PASS' }
    if (-not [bool]$pr.isolation_verified) { $fail = 'GUEST_ISOLATION_NOT_VERIFIED' }
    if ([string]$rcv.status -cne 'PASS') { $fail = 'RECOVERY_NOT_PASS' }
    if ([string]$rcv.windows_snapshot -cne $WindowsSnapshot) { $fail = 'RECOVERY_SNAPSHOT_NOT_V11' }
    if (-not [bool]$rcv.network_exactly_restored) { $fail = 'HOST_NETWORK_NOT_RESTORED' }
    if (-not (Test-Path -LiteralPath (Join-Path $runDir 'capture_archive.zip') -PathType Leaf)) { $fail = 'CAPTURE_ARCHIVE_MISSING' }

    $officialNow = @(Get-ChildItem -LiteralPath $OfficialRoot -Directory -ErrorAction SilentlyContinue).Count
    if ($officialNow -ne ($before.Count + 1)) { $fail = 'OFFICIAL_PACKAGE_COUNT_NOT_PLUS_ONE' }

    if ($fail) {
        $entry.failure = $fail
        $Script:Results += [pscustomobject]$entry
        $halted = $true; $haltReason = $p.run_id + ': ' + $fail
        Write-Host ('OFFICIAL HALT: ' + $p.run_id + ' -> ' + $fail + '. Evidence: ' + $runDir) -ForegroundColor Red
        break
    }
    $entry.status = 'PASS'
    $slots += [int]$entry.official_slots_consumed
    $Script:Results += [pscustomobject]$entry
    Write-Host ('OFFICIAL RUN PASS: ' + $p.run_id + '  slots=' + $entry.official_slots_consumed + '/' + $slots + '  termination=' + $entry.termination_mode + '  canaries=' + $entry.canaries_modified + '/' + $entry.canary_total + '  telemetry=' + $entry.telemetry_rows) -ForegroundColor Green
    Write-Host ('   evidence: ' + $runDir) -ForegroundColor DarkGray
}

# ------------------------------------------------------------------ the campaign summary
$passed = @($Script:Results | Where-Object { $_.status -ceq 'PASS' }).Count
$failed = @($Script:Results | Where-Object { $_.status -ceq 'FAIL' }).Count
$summary = [ordered]@{
    schema_version = '1.0'; gate = 'RANSOMWARE_OFFICIAL_RUN'
    authorisation = 'OWNER 2026-11-15 (console instruction; DECISIONS.md D-167), conditioned on the D-166 fresh 10-family Windows preflight 10/10 PASS'
    official_run = $true; official_campaign_slots_consumed = $slots
    windows_baseline = $WindowsSnapshot; ubuntu_baseline = $UbuntuSnapshot
    ubuntu_official_slots_consumed = 20
    families_planned = 10; runs_planned = 20
    runs_attempted = $Script:Results.Count; runs_passed = $passed; runs_failed = $failed
    halt_reason = $haltReason; results = @($Script:Results | ForEach-Object { $_ })
    manifest_windows_pending_rows_consumed = $slots
    timestamp = [DateTime]::UtcNow.ToString('o')
}
Write-Json $summaryJson $summary

if ($halted -or $failed -gt 0) {
    Write-Host ''
    Write-Host ('OFFICIAL WINDOWS CAMPAIGN BLOCK INCOMPLETE: {0}/20 PASS, halted at: {1}' -f $passed, $haltReason) -ForegroundColor Red
    Write-Host ('Evidence (failing run kept, remaining slots unconsumed): summary: ' + $summaryJson) -ForegroundColor Red
    exit 1
}
Write-Host ''
Write-Host ('ALL 20 WINDOWS OFFICIAL RANSOMWARE RUNS PASSED. Official campaign slots consumed = {0} (Windows 20; Ubuntu 20; total 40).' -f $slots) -ForegroundColor Green
Write-Host ('Summary: ' + $summaryJson) -ForegroundColor Green
exit 0
