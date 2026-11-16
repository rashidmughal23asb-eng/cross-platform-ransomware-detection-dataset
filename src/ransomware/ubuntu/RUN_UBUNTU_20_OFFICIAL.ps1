<#
    RUN_UBUNTU_20_OFFICIAL.ps1
    ===========================
    The OFFICIAL Ubuntu ransomware campaign block: 20 official runs = the 10 qualified
    families x 2 repetitions, executed ONE AT A TIME, sequentially, in campaign execution
    order (21..40).

    AUTHORISATION: the owner authorised the official 20 Ubuntu ransomware runs on
    2026-11-12 (DECISIONS.md D-129), on the condition that the 10-family preflight on the
    FROZEN 236-file canary corpus had passed 10/10 - it did (D-128).

    WHAT THIS SCRIPT DOES
      * drives the FROZEN production controller (RANSOMWARE_Official_Run_Controller.ps1)
        with RunMode=Official, once per manifest row, in a SEPARATE child process so each
        run is a complete, independent cycle: boot from the frozen V11 baseline -> stage the
        sample and the frozen 236-file canary corpus -> telemetry -> execute the sample under
        the family's FROZEN invocation contract under a 60 s bounded observation with the
        90 s watchdog -> canary integrity -> evidence pack -> power off -> revert to V11 ->
        restore the host network;
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
      run consumes none. This script records the per-run and the total in its summary.

    THE MANIFESTS ARE NOT MODIFIED BY THIS SCRIPT. The manifest's status column stays
    PENDING (the authoritative outcome of each run lives in its evidence package and in
    this script's summary), because the manifests are frozen.

    Usage:
      powershell -NoProfile -ExecutionPolicy Bypass -File RUN_UBUNTU_20_OFFICIAL.ps1
      powershell -NoProfile -ExecutionPolicy Bypass -File RUN_UBUNTU_20_OFFICIAL.ps1 -DryRun
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
$UbuntuVmxPath = 'D:\Ubuntu 24.04\Ubuntu.vmx'
$WindowsVmxPath = 'D:\Windows 11\Windows 11.vmx'
$UbuntuSnapshot = 'P5G_V11_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261112'
$WindowsSnapshot = 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013'
$Manifest40 = Join-Path $CampaignRoot '01_SHARED\manifests\RANSOMWARE_40_RUN_MANIFEST.csv'
$Manifest100 = Join-Path $CampaignRoot '01_SHARED\manifests\CAMPAIGN_100_RUN_MANIFEST.csv'
$FamilySet = Join-Path $CampaignRoot '01_SHARED\sample_selection\UBUNTU_V11_FINAL_FAMILY_SET_20261112\UBUNTU_V11_FINAL_FAMILY_SET_MANIFEST.csv'
$OfficialRoot = Join-Path $CampaignRoot '05_UBUNTU\RANSOMWARE\official_runs'
$PreflightRoot = Join-Path $CampaignRoot '05_UBUNTU\RANSOMWARE\preflight_runs'
$ResultsRoot = Join-Path $CampaignRoot '05_UBUNTU\RANSOMWARE\results'

# every input is pinned; if any of them moved the campaign does not start
$Pinned = [ordered]@{
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\RANSOMWARE_Official_Run_Controller.ps1' = '0781bd6f40302818a09c95b29ab10bf2912bc7d35f9b18b1a5a6ff904f3b4306'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\RANSOMWARE_Guest_Official.sh'           = '2fab62cbbc4f667e175aaf92b75f242100e8d838324b4b4569d6f2d21bdda829'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\UbuntuNativeBridge.ps1'                = '28d222147a924d1b2da2003bf9f30ae91746c8cbf1d6e79b96237ffe89837b21'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\UbuntuNativeBase.ps1'                  = '7b79790eb2f424a83c1626be95b85fc373f34334c4ab441afb726ffde5f910f1'
    '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\UBUNTU_Compound_Trace.bt'             = '702e64b98d2d854828530c8f021d99e47f931ea1994232c3277f0758b2665aae'
    '01_SHARED\manifests\RANSOMWARE_40_RUN_MANIFEST.csv'                                                  = '3f1065c7030b36e86f9f5cf9fa6de8bf533d3b9b4fb96307e02b29f4e563a6e6'
    '01_SHARED\manifests\CAMPAIGN_100_RUN_MANIFEST.csv'                                                  = 'db9dd99fbeaccc24a41fed47a0f933ae14ed2cd5c42b42f0b72a9232d2d9ef53'
    '01_SHARED\sample_selection\UBUNTU_V11_FINAL_FAMILY_SET_20261112\UBUNTU_V11_FINAL_FAMILY_SET_MANIFEST.csv' = '574d0e237e57b9bfc58918dacd61020ddb0244975e5190ecdbdef4e077c3dad3'
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

# ------------------------------------------------------------------ the plan (20 runs)
$Rows40 = @(Import-Csv -LiteralPath $Manifest40)
$Rows100 = @(Import-Csv -LiteralPath $Manifest100)
$Families = @{}
foreach ($r in (Import-Csv -LiteralPath $FamilySet)) { $Families[[string]$r.family] = $r }
$Plan = @()
foreach ($r in @($Rows40 | Where-Object { $_.platform -ceq 'Ubuntu' } | Sort-Object { [int]$_.execution_order })) {
    $fs = $Families[[string]$r.family_stratum]
    Assert-True ($null -ne $fs) ('FAMILY_NOT_IN_THE_FROZEN_FAMILY_SET:' + $r.family_stratum)
    Assert-True ([string]$fs.sha256 -ceq [string]$r.sample_sha256) ('FAMILY_SET_IDENTITY_MISMATCH:' + $r.family_stratum)
    Assert-True ([string]$fs.guest_staging_path -ceq [string]$r.sample_guest_path) ('FAMILY_SET_GUEST_PATH_MISMATCH:' + $r.family_stratum)
    Assert-True ([string]$r.snapshot_baseline -ceq $UbuntuSnapshot) ('UBUNTU_ROW_BASELINE_NOT_V11:' + $r.run_id)
    $c = @($Rows100 | Where-Object { $_.run_id -ceq $r.run_id })
    Assert-True ($c.Count -eq 1) ('CAMPAIGN_ROW_NOT_FOUND:' + $r.run_id)
    Assert-True ([string]$c[0].snapshot_baseline -ceq $UbuntuSnapshot) ('CAMPAIGN_ROW_BASELINE_NOT_V11:' + $r.run_id)
    $Plan += [pscustomobject]@{
        run_id = [string]$r.run_id
        execution_order = [int]$r.execution_order
        sample_run_id = [string]$r.sample_run_id
        family = [string]$r.family_stratum
        contract = [string]$fs.frozen_contract
        split = [string]$r.split
        repetition = [string]$r.repetition
        scenario_run_id = [string]$r.sample_run_id + '-' + [string]$r.repetition
        fixture_seed = [string]$c[0].fixture_seed
        sample_sha256 = [string]$r.sample_sha256
        sample_bytes = [string]$r.sample_bytes
        sample_guest_path = [string]$r.sample_guest_path
        mode_octal = '0000'
        read_only = 'True'
        status = 'PENDING'
    }
}
Assert-True ($Plan.Count -eq 20) ('PLAN_RUN_COUNT_NOT_20:' + $Plan.Count)
Assert-True ((@($Plan.family | Sort-Object -Unique).Count) -eq 10) 'PLAN_FAMILY_COUNT_NOT_10'

Write-Host ''
Write-Host ('=== OFFICIAL UBUNTU CAMPAIGN BLOCK: 20 runs = 10 families x 2 repetitions ===') -ForegroundColor Cyan
Write-Host ('{0,-5} {1,-16} {2,-6} {3,-6} {4,-6} {5,-38} {6}' -f 'ord', 'run_id', 'family', 'split', 'rep', 'frozen contract', 'fixture seed')
foreach ($p in $Plan) {
    Write-Host ('{0,-5} {1,-16} {2,-6} {3,-6} {4,-6} {5,-38} {6}' -f $p.execution_order, $p.run_id, $p.family, $p.split, $p.repetition, $p.contract, $p.fixture_seed)
}
Write-Host ''

if ($DryRun) { Write-Host 'DRY RUN: nothing was executed; no slot was consumed.' -ForegroundColor Yellow; exit 0 }

# ------------------------------------------------------------------ preconditions
$free = [math]::Round((Get-PSDrive -Name D).Free / 1GB, 2)
Assert-True (-not (Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_MUST_BE_OFF_PRE_RUN'
Assert-True (-not (Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_MUST_BE_OFF_PRE_RUN'
Assert-True ((Get-CurrentSnapshotName $UbuntuVmxPath) -ceq $UbuntuSnapshot) ('UBUNTU_CURRENT_SNAPSHOT_NOT_V11:' + (Get-CurrentSnapshotName $UbuntuVmxPath))
Assert-True ((Get-CurrentSnapshotName $WindowsVmxPath) -ceq $WindowsSnapshot) 'WINDOWS_CURRENT_SNAPSHOT_MISMATCH'
Assert-True ($free -ge $MinFreeGiB) ('DISK_BELOW_MIN_FREE:' + $free)
$officialBefore = @(Get-ChildItem -LiteralPath $OfficialRoot -Directory -ErrorAction SilentlyContinue).Count
Assert-True ($officialBefore -eq 0) ('OFFICIAL_RUNS_NOT_EMPTY_AT_START:' + $officialBefore)
$preflightPkgs = @(Get-ChildItem -LiteralPath $PreflightRoot -Directory -Filter 'RAN_UBU_*' -ErrorAction SilentlyContinue).Count
Assert-True ($preflightPkgs -eq 10) ('PREFLIGHT_SERIES_INCOMPLETE:' + $preflightPkgs + ' of 10')
$preSummary = @(Get-ChildItem -LiteralPath $PreflightRoot -Filter 'PREFLIGHT_SUMMARY*.json' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1)
Assert-True ($preSummary.Count -eq 1) 'PREFLIGHT_SUMMARY_MISSING'
$pre = Get-Content -LiteralPath $preSummary[0].FullName -Raw | ConvertFrom-Json
Assert-True ([string]$pre.status -ceq 'PASS' -and [int]$pre.families_passed -eq 10 -and [int]$pre.families_failed -eq 0) 'PREFLIGHT_SERIES_NOT_PASS_10_OF_10'
Assert-True ([int]$pre.official_campaign_slots_consumed -eq 0) 'PREFLIGHT_CONSUMED_SLOTS'
Write-Host ('OFFICIAL: preconditions PASS (D: free {0} GiB, both VMs off, Ubuntu current snapshot = V11, official_runs empty, preflight 10/10 PASS).' -f $free) -ForegroundColor Green

# ------------------------------------------------------------------ the runs
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$summaryJson = Join-Path $ResultsRoot ('OFFICIAL_UBUNTU_20_SUMMARY_' + $stamp + '.json')
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
        '-ProcessDensityRole', 'MALICIOUS_PRIMARY_SUBJECT', '-EvidenceArchiveFormat', 'tar.gz',
        '-TelemetryAdapter', 'bpftrace+auditd', '-Status', $p.status
    )
    & powershell @cmd
    $rc = $LASTEXITCODE

    $after = @(Get-ChildItem -LiteralPath $OfficialRoot -Directory -ErrorAction SilentlyContinue)
    $new = @($after | Where-Object { $before -notcontains $_.Name })
    $runDir = if ($new.Count -eq 1) { $new[0].FullName } else { '' }

    $entry = [ordered]@{
        run_id = $p.run_id; execution_order = $p.execution_order; family = $p.family
        split = $p.split; repetition = $p.repetition; frozen_contract = $p.contract
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
    $entry.argv_used = [string]$sx.sample_argv
    $entry.canaries_modified = [string]$ci.canary_mismatches
    $entry.canary_total = [string]$ci.canary_total
    $entry.telemetry_rows = [string]$tc.telemetry_rows

    $expectedArgv = ($p.contract -replace '<CANARY>', [string]$pr.canary_root)
    if ([string]$sx.sample_argv -cne $expectedArgv) { $fail = 'ARGV_NOT_THE_FROZEN_CONTRACT' }
    if ([int]$pr.canary_count -ne 236) { $fail = 'CANARY_COUNT_NOT_236' }
    if ([string]$pr.status -cne 'PASS') { $fail = 'SAMPLE_PREPARE_NOT_PASS' }
    if (-not [bool]$pr.isolation_verified) { $fail = 'GUEST_ISOLATION_NOT_VERIFIED' }
    if ([string]$rcv.status -cne 'PASS') { $fail = 'RECOVERY_NOT_PASS' }
    if ([string]$rcv.ubuntu_snapshot -cne $UbuntuSnapshot) { $fail = 'RECOVERY_SNAPSHOT_NOT_V11' }
    if (-not [bool]$rcv.network_restored) { $fail = 'HOST_NETWORK_NOT_RESTORED' }
    if (-not (Test-Path -LiteralPath (Join-Path $runDir 'capture_archive.tar.gz') -PathType Leaf)) { $fail = 'CAPTURE_ARCHIVE_MISSING' }

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
    Write-Host ('OFFICIAL RUN PASS: ' + $p.run_id + '  slots=' + $entry.official_slots_consumed + '/' + $slots + '  termination=' + $entry.termination_mode + '  canaries=' + $entry.canaries_modified + '/' + $entry.canary_total + '  telemetry=' + $entry.telemetry_rows + ' rows') -ForegroundColor Green
    Write-Host ('   evidence: ' + $runDir) -ForegroundColor DarkGray
}

# ------------------------------------------------------------------ the campaign summary
$passed = @($Script:Results | Where-Object { $_.status -ceq 'PASS' }).Count
$failed = @($Script:Results | Where-Object { $_.status -ne 'PASS' }).Count
$summary = [ordered]@{
    schema_version = '1.0'
    gate = 'OFFICIAL_UBUNTU_20'
    generated_utc = [DateTime]::UtcNow.ToString('o')
    status = if ($halted) { 'FAIL' } elseif ($passed -eq 20) { 'PASS' } else { 'INCOMPLETE' }
    authorisation = 'owner-authorised 2026-11-12 (D-129), conditional on the 10-family preflight passing 10/10 (D-128)'
    runs_planned = $Plan.Count
    runs_attempted = $Script:Results.Count
    runs_passed = $passed
    runs_failed = $failed
    official_campaign_slots_consumed = $slots
    halt_reason = $haltReason
    ubuntu_baseline = $UbuntuSnapshot
    windows_baseline = $WindowsSnapshot
    canary_corpus = 'FROZEN 236-file common corpus (Corpus V2)'
    results = $Script:Results
}
Write-Json $summaryJson $summary
Write-Host ''
Write-Host ('OFFICIAL UBUNTU SUMMARY: ' + $passed + '/20 passed, ' + $failed + ' failed, official slots consumed=' + $slots + '; summary: ' + $summaryJson) -ForegroundColor $(if ($halted) { 'Red' } else { 'Green' })
if ($halted) { Write-Host ('HALTED: ' + $haltReason + ' - the remaining runs were not attempted and their slots stay unconsumed.') -ForegroundColor Red; exit 1 }
if ($passed -ne 20) { Write-Host 'INCOMPLETE: not all twenty official runs passed.' -ForegroundColor Red; exit 1 }
Write-Host 'ALL TWENTY OFFICIAL UBUNTU RANSOMWARE RUNS PASSED.' -ForegroundColor Green
exit 0
