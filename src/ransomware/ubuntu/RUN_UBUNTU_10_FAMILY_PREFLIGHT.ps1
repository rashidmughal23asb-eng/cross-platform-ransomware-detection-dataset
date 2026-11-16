<#
    RUN_UBUNTU_10_FAMILY_PREFLIGHT.ps1
    ==================================
    The 10-family Ubuntu ransomware PREFLIGHT (D-119, owner-authorised preparation).

    WHAT THIS IS
      A zero-official-slot rehearsal of the complete official Ubuntu ransomware path,
      once per qualified family, in frozen_rank order. Every preflight executes the
      family's frozen sample under its frozen invocation contract through the FROZEN
      production controller (RANSOMWARE_Official_Run_Controller.ps1, RunMode=Preflight),
      so that the official runs are only authorised after the whole path has been
      proven for all ten families.

    WHAT THIS IS NOT
      It is NOT an official run. RunMode=Preflight writes to
      05_UBUNTU\RANSOMWARE\preflight_runs\ and consumes 0 of the 40 official campaign
      slots (the controller hard-codes official_campaign_slots_consumed=0 for every
      non-Official mode). It does not touch the Windows half, the manifests, the
      snapshots, the canary corpus, the timing policy or the telemetry.

    RULES HONOURED
      * The frozen per-family invocation contract is used verbatim - it is read by the
        controller from the frozen family set manifest (the single argv-table authority);
        this driver never invents a token.
      * HALT ON FIRST FAILURE: the exact failure plus the evidence package is written,
        the remaining families are NOT attempted, and the official runs stay unauthorised.
      * The pre-existing hashes of every input are pinned: if any of them moved, the
        driver refuses to start instead of rehearsing an unknown state.
      * After every preflight the driver asserts that the official slot count is still 0
        and that the guest was reverted to the V11 baseline with the host restored.
      * The argv actually used is verified against the frozen contract, token by token,
        from the sample_execute receipt.

    EXECUTION
      The owner runs this. The agent prepares and validates; it never executes a
      ransomware sample. Each preflight boots the guest and executes the live sample
      inside it - that is the point of the rehearsal.

    USAGE
      # 1. print the plan and execute nothing
      powershell -NoProfile -ExecutionPolicy Bypass -File RUN_UBUNTU_10_FAMILY_PREFLIGHT.ps1 -DryRun

      # 2. run all ten, halting at the first failure
      powershell -NoProfile -ExecutionPolicy Bypass -File RUN_UBUNTU_10_FAMILY_PREFLIGHT.ps1

      # 3. run one family only (for triage)
      powershell -NoProfile -ExecutionPolicy Bypass -File RUN_UBUNTU_10_FAMILY_PREFLIGHT.ps1 -Only Conti
#>
[CmdletBinding()]
param(
    [string]$CampaignRoot = 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs',
    [int]$MaxPreflights = 0,
    [switch]$DryRun,
    [switch]$SelfTest,
    [string[]]$Only = @(),
    [double]$MinFreeGiB = 6.0,
    [double]$DiskReserveGiB = 2.5
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Script:Results = @()
$Script:Attempt = 0
$Script:RunRoot = $null

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw ('PREFLIGHT_FAILURE:' + $Message) } }
function SHA([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-Json([string]$Path, [object]$Object) {
    $d = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    [IO.File]::WriteAllText($Path, (($Object | ConvertTo-Json -Depth 20) + "`r`n"), (New-Object Text.UTF8Encoding($false)))
}
function Write-Log([string]$Level, [string]$Message) {
    $line = '{0} [{1}] {2}' -f [DateTime]::UtcNow.ToString('o'), $Level, $Message
    Write-Host $line
    if ($Script:RunRoot) { Add-Content -LiteralPath (Join-Path $Script:RunRoot 'PREFLIGHT_ORCHESTRATOR.log') -Value $line -Encoding UTF8 }
}

# ------------------------------------------------------------------ pinned inputs
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
$UbuntuSnapshot = 'P5G_V11_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261112'
$WindowsSnapshot = 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013'
$VmrunPath = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$UbuntuVmxPath = 'D:\Ubuntu 24.04\Ubuntu.vmx'
$WindowsVmxPath = 'D:\Windows 11\Windows 11.vmx'
$PreflightRoot = Join-Path $CampaignRoot '05_UBUNTU\RANSOMWARE\preflight_runs'
$OfficialRoot = Join-Path $CampaignRoot '05_UBUNTU\RANSOMWARE\official_runs'

# ------------------------------------------------------------------ administrator + pins
$P = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Assert-True ($P.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'
foreach ($rel in $Pinned.Keys) {
    $p = Join-Path $CampaignRoot $rel
    Assert-True (Test-Path -LiteralPath $p -PathType Leaf) ('PINNED_INPUT_MISSING:' + $rel)
    $actual = SHA $p
    Assert-True ($actual -ceq $Pinned[$rel]) ('PINNED_INPUT_DRIFT:' + $rel + ':expected=' + $Pinned[$rel] + ':actual=' + $actual)
}
Write-Host 'PREFLIGHT: every pinned input matches its recorded hash.' -ForegroundColor Green

# ------------------------------------------------------------------ the plan
$Manifest40 = Join-Path $CampaignRoot '01_SHARED\manifests\RANSOMWARE_40_RUN_MANIFEST.csv'
$Manifest100 = Join-Path $CampaignRoot '01_SHARED\manifests\CAMPAIGN_100_RUN_MANIFEST.csv'
$FamilySet = Join-Path $CampaignRoot '01_SHARED\sample_selection\UBUNTU_V11_FINAL_FAMILY_SET_20261112\UBUNTU_V11_FINAL_FAMILY_SET_MANIFEST.csv'
$Rows40 = @(Import-Csv -LiteralPath $Manifest40)
$Rows100 = @(Import-Csv -LiteralPath $Manifest100)
$Families = @{}
foreach ($r in (Import-Csv -LiteralPath $FamilySet)) { $Families[[string]$r.family] = $r }

$Plan = @()
foreach ($r in @($Rows40 | Where-Object { $_.platform -ceq 'Ubuntu' -and $_.repetition -ceq 'A' })) {
    $fs = $Families[[string]$r.family_stratum]
    Assert-True ($null -ne $fs) ('FAMILY_NOT_IN_THE_FROZEN_FAMILY_SET:' + $r.family_stratum)
    Assert-True ([string]$fs.sha256 -ceq [string]$r.sample_sha256) ('FAMILY_SET_IDENTITY_MISMATCH:' + $r.family_stratum)
    Assert-True ([string]$fs.guest_staging_path -ceq [string]$r.sample_guest_path) ('FAMILY_SET_GUEST_PATH_MISMATCH:' + $r.family_stratum)
    Assert-True ([string]$r.snapshot_baseline -ceq $UbuntuSnapshot) ('UBUNTU_ROW_BASELINE_NOT_V11:' + $r.run_id)
    $c = @($Rows100 | Where-Object { $_.run_id -ceq $r.run_id })
    Assert-True ($c.Count -eq 1) ('CAMPAIGN_ROW_NOT_FOUND:' + $r.run_id)
    Assert-True ([string]$c[0].snapshot_baseline -ceq $UbuntuSnapshot) ('CAMPAIGN_ROW_BASELINE_NOT_V11:' + $r.run_id)
    $Plan += [pscustomobject]@{
        frozen_rank      = [int]$fs.frozen_rank
        family           = [string]$r.family_stratum
        contract         = [string]$fs.frozen_contract
        run_id           = [string]$r.run_id
        execution_order  = [int]$r.execution_order
        sample_run_id    = [string]$r.sample_run_id
        split            = [string]$r.split
        repetition       = [string]$r.repetition
        scenario_run_id  = [string]$r.sample_run_id + '-' + [string]$r.repetition
        fixture_seed     = [string]$c[0].fixture_seed
        sample_sha256    = [string]$r.sample_sha256
        sample_bytes     = [string]$r.sample_bytes
        sample_guest_path= [string]$r.sample_guest_path
        mode_octal       = '0000'      # the controller validates ^[0-7]{4}$; the manifest's '000' is the same value
        read_only        = 'True'
        status           = 'PENDING'
    }
}
$Plan = @($Plan | Sort-Object execution_order)   # the campaign order the official runs will use
Assert-True ($Plan.Count -eq 10) ('PLAN_FAMILY_COUNT_NOT_10:' + $Plan.Count)
if ($Only.Count -gt 0) { $Plan = @($Plan | Where-Object { $Only -contains $_.family }) }
Assert-True ($Plan.Count -gt 0) 'PLAN_EMPTY_AFTER_FILTER'

Write-Host ''
Write-Host ('=== UBUNTU 10-FAMILY RANSOMWARE PREFLIGHT PLAN ({0} family/families) ===' -f $Plan.Count) -ForegroundColor Cyan
Write-Host ('{0,-4} {1,-16} {2,-13} {3,-4} {4,-6} {5,-34} {6}' -f 'rank', 'family', 'run_id', 'ord', 'split', 'frozen contract', 'guest staging root')
foreach ($p in $Plan) {
    $root = ($p.sample_guest_path -split '/Samples')[0]
    Write-Host ('{0,-4} {1,-16} {2,-13} {3,-4} {4,-6} {5,-34} {6}' -f $p.frozen_rank, $p.family, $p.run_id, $p.execution_order, $p.split, $p.contract, $root)
}
Write-Host ''
Write-Host ('Official campaign slots consumed by this script: 0 (RunMode=Preflight writes to preflight_runs\ and never to official_runs\).') -ForegroundColor Yellow

if ($DryRun) { Write-Host 'DRY RUN: nothing was executed.' -ForegroundColor Yellow; exit 0 }

# ------------------------------------------------------------------ self-test
# Formats EVERY line the real run prints, with the real plan data, and exits. It touches no
# VM, no controller and no sample - it exists so that a malformed format string can never
# again reach the owner in the middle of a preflight series (D-121).
if ($SelfTest) {
    Write-Host '=== PREFLIGHT SELF-TEST (formatting only - no VM, no controller, no sample) ===' -ForegroundColor Cyan
    $n = 0
    foreach ($p in $Plan) {
        $n++
        Write-Host ('=' * 92)
        Write-Host ('PREFLIGHT {0}/10  {1}  {2}  contract: {3}' -f $n, $p.run_id, $p.family, $p.contract) -ForegroundColor Cyan
        Write-Host ('=' * 92)
        $entry = [pscustomobject]@{ argv_used = '<CANARY-substituted>'; termination_mode = 'NATURAL_EXIT'; recovery_verified = $true }
        Write-Host ('PREFLIGHT PASS: ' + $p.family + '  argv=' + $entry.argv_used + '  evidence=<self-test>') -ForegroundColor Green
    }
    Write-Host ('PREFLIGHT SUMMARY (self-test): ' + $Plan.Count + '/' + $Plan.Count + ' formatted; official slots consumed=0; run_id=' + $Plan[0].run_id) -ForegroundColor Green
    Write-Host 'SELF-TEST PASS: every printed line formatted successfully. Nothing was executed.' -ForegroundColor Green
    exit 0
}

# ------------------------------------------------------------------ host preconditions
function Get-VmOn([string]$Vmrun, [string]$Vmx) {
    $out = & $Vmrun list 2>$null
    return (@($out | Where-Object { $_ -and ([string]$_).Trim().ToLowerInvariant() -eq $Vmx.ToLowerInvariant() }).Count -gt 0)
}
function Get-CurrentSnapshotName([string]$Vmx) {
    $vmsd = [IO.Path]::ChangeExtension($Vmx, 'vmsd')
    $lines = [IO.File]::ReadAllLines($vmsd)
    $cur = ''; $uidToIndex = @{}; $indexToName = @{}
    foreach ($l in $lines) {
        if ($l -match '^\s*snapshot\.current\s*=\s*"(\d+)"') { $cur = $Matches[1] }
        if ($l -match '^\s*snapshot(\d+)\.uid\s*=\s*"(\d+)"') { $uidToIndex[$Matches[2]] = $Matches[1] }
        if ($l -match '^\s*snapshot(\d+)\.displayName\s*=\s*"(.*)"') { $indexToName[$Matches[1]] = $Matches[2] }
    }
    if ($uidToIndex.ContainsKey($cur) -and $indexToName.ContainsKey($uidToIndex[$cur])) { return $indexToName[$uidToIndex[$cur]] }
    return ''
}
Assert-True (-not (Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_MUST_BE_OFF_PRE_PREFLIGHT'
Assert-True (-not (Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_MUST_BE_OFF_PRE_PREFLIGHT'
Assert-True ((Get-CurrentSnapshotName $UbuntuVmxPath) -ceq $UbuntuSnapshot) ('UBUNTU_CURRENT_SNAPSHOT_NOT_V11:' + (Get-CurrentSnapshotName $UbuntuVmxPath))
Assert-True ((Get-CurrentSnapshotName $WindowsVmxPath) -ceq $WindowsSnapshot) 'WINDOWS_CURRENT_SNAPSHOT_MISMATCH'
$free = [math]::Round((Get-PSDrive -Name D).Free / 1GB, 2)
Assert-True ($free -ge $MinFreeGiB) ('DISK_BELOW_MIN_FREE:' + $free + 'GiB<' + $MinFreeGiB + 'GiB')
$officialBefore = @(Get-ChildItem -LiteralPath $OfficialRoot -Directory -ErrorAction SilentlyContinue).Count
Assert-True ($officialBefore -eq 0) ('OFFICIAL_RUNS_NOT_EMPTY_BEFORE_PREFLIGHT:' + $officialBefore)
Write-Host ('PREFLIGHT: host preconditions PASS (D: free {0} GiB, both VMs off, Ubuntu current snapshot = V11, official_runs empty).' -f $free) -ForegroundColor Green

# ------------------------------------------------------------------ run
$Controller = Join-Path $CampaignRoot '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\RANSOMWARE_Official_Run_Controller.ps1'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$summaryJson = Join-Path $PreflightRoot ('PREFLIGHT_SUMMARY_' + $stamp + '.json')
$halted = $false
$haltReason = ''

foreach ($p in $Plan) {
    if ($MaxPreflights -gt 0 -and $Script:Attempt -ge $MaxPreflights) { Write-Host 'PREFLIGHT: -MaxPreflights reached; stopping.' -ForegroundColor Yellow; break }
    $Script:Attempt++
    Write-Host ''
    Write-Host ('=' * 92) -ForegroundColor Cyan
    Write-Host ('PREFLIGHT {0}/10  {1}  {2}  contract: {3}' -f $Script:Attempt, $p.run_id, $p.family, $p.contract) -ForegroundColor Cyan
    Write-Host ('=' * 92) -ForegroundColor Cyan

    $before = @(Get-ChildItem -LiteralPath $PreflightRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $cmd = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Controller,
        '-CampaignRoot', $CampaignRoot, '-RunMode', 'Preflight',
        '-VmrunPath', $VmrunPath, '-VMwareGuiPath', 'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe',
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

    $after = @(Get-ChildItem -LiteralPath $PreflightRoot -Directory -ErrorAction SilentlyContinue)
    $new = @($after | Where-Object { $before -notcontains $_.Name })
    $runDir = if ($new.Count -eq 1) { $new[0].FullName } else { '' }
    $Script:RunRoot = if ($runDir) { $runDir } else { $PreflightRoot }

    $entry = [ordered]@{
        frozen_rank = $p.frozen_rank; family = $p.family; run_id = $p.run_id; frozen_contract = $p.contract
        exit_code = $rc; evidence_package = $runDir; status = 'FAIL'; failure = ''
        official_slots_consumed = $null; argv_used = ''; termination_mode = ''; watchdog_fired = $null
        recovery_verified = $false; guest_snapshot = ''
    }

    if ($rc -ne 0) {
        $entry.failure = 'CONTROLLER_EXIT_' + $rc
        $Script:Results += [pscustomobject]$entry
        $halted = $true; $haltReason = $p.family + ': controller exit ' + $rc
        Write-Host ('PREFLIGHT HALT: ' + $p.family + ' failed (controller exit ' + $rc + '). Evidence: ' + $runDir) -ForegroundColor Red
        break
    }

    # ---- verify the evidence package ----
    $rr = Get-Content -LiteralPath (Join-Path $runDir 'RUN_RESULT.json') -Raw | ConvertFrom-Json
    $entry.official_slots_consumed = [int]$rr.official_campaign_slots_consumed
    $entry.termination_mode = [string]$rr.termination_mode
    $entry.watchdog_fired = [bool]$rr.watchdog_fired
    $entry.recovery_verified = [bool]$rr.recovery_verified
    $fail = $null
    if ([string]$rr.status -cne 'PASS') { $fail = 'RUN_RESULT_NOT_PASS' }
    if ([string]$rr.run_mode -cne 'Preflight') { $fail = 'RUN_MODE_NOT_PREFLIGHT' }
    if ([bool]$rr.official_run) { $fail = 'OFFICIAL_RUN_FLAG_SET' }
    if ([int]$rr.official_campaign_slots_consumed -ne 0) { $fail = 'OFFICIAL_SLOT_CONSUMED' }
    if ([int]$rr.execution_order -ne $p.execution_order) { $fail = 'EXECUTION_ORDER_MISMATCH' }
    if ([string]$rr.family_stratum -cne $p.family) { $fail = 'FAMILY_MISMATCH' }
    if (-not [bool]$rr.watchdog_armed) { $fail = 'WATCHDOG_NOT_ARMED' }
    if (-not [bool]$rr.recovery_verified) { $fail = 'RECOVERY_NOT_VERIFIED' }

    # the argv actually used must be the frozen contract, token for token
    $sr = Get-Content -LiteralPath (Join-Path $runDir 'evidence\sample_execute_receipt.json') -Raw | ConvertFrom-Json
    $pr = Get-Content -LiteralPath (Join-Path $runDir 'evidence\sample_prepare_receipt.json') -Raw | ConvertFrom-Json
    $entry.argv_used = [string]$sr.sample_argv
    $expectedArgv = ($p.contract -replace '<CANARY>', [string]$pr.canary_root)
    if ([string]$sr.sample_argv -cne $expectedArgv) { $fail = 'ARGV_NOT_THE_FROZEN_CONTRACT' }
    if ([string]$pr.status -cne 'PASS') { $fail = 'SAMPLE_PREPARE_NOT_PASS' }
    if (-not [bool]$pr.isolation_verified) { $fail = 'GUEST_ISOLATION_NOT_VERIFIED' }
    # D-125: the FROZEN common canary corpus (Corpus V2) is 236 files. A preflight that
    # staged any other corpus is not a valid rehearsal of the official methodology.
    if ([int]$pr.canary_count -ne 236) { $fail = 'CANARY_COUNT_NOT_236' }

    $fv = Get-Content -LiteralPath (Join-Path $runDir 'RUN_FULL_VERIFICATION.json') -Raw | ConvertFrom-Json
    if ([string]$fv.status -cne 'PASS' -or [int]$fv.fail -ne 0) { $fail = 'PACKAGE_SELF_VERIFICATION_NOT_PASS' }

    $rcv = Get-Content -LiteralPath (Join-Path $runDir 'recovery\POST_RECOVERY_VERIFICATION.json') -Raw | ConvertFrom-Json
    $entry.guest_snapshot = [string]$rcv.ubuntu_snapshot
    if ([string]$rcv.status -cne 'PASS') { $fail = 'RECOVERY_NOT_PASS' }
    if ([string]$rcv.ubuntu_snapshot -cne $UbuntuSnapshot) { $fail = 'RECOVERY_SNAPSHOT_NOT_V11' }
    if (-not [bool]$rcv.network_restored) { $fail = 'HOST_NETWORK_NOT_RESTORED' }

    # the official slot count must still be zero
    $officialNow = @(Get-ChildItem -LiteralPath $OfficialRoot -Directory -ErrorAction SilentlyContinue).Count
    if ($officialNow -ne 0) { $fail = 'OFFICIAL_RUNS_DIR_NOT_EMPTY' }

    if ($fail) {
        $entry.failure = $fail
        $Script:Results += [pscustomobject]$entry
        $halted = $true; $haltReason = $p.family + ': ' + $fail
        Write-Host ('PREFLIGHT HALT: ' + $p.family + ' -> ' + $fail + '. Evidence: ' + $runDir) -ForegroundColor Red
        break
    }
    $entry.status = 'PASS'
    $Script:Results += [pscustomobject]$entry
    Write-Host ('PREFLIGHT PASS: ' + $p.family + '  argv=' + $entry.argv_used + '  evidence=' + $runDir) -ForegroundColor Green
}

# ------------------------------------------------------------------ summary
$passed = @($Script:Results | Where-Object { $_.status -ceq 'PASS' }).Count
$failed = @($Script:Results | Where-Object { $_.status -ne 'PASS' }).Count
$officialAfter = @(Get-ChildItem -LiteralPath $OfficialRoot -Directory -ErrorAction SilentlyContinue).Count
$summary = [ordered]@{
    schema_version = '1.0'
    gate = 'UBUNTU_10_FAMILY_RANSOMWARE_PREFLIGHT'
    generated_utc = [DateTime]::UtcNow.ToString('o')
    status = if ($halted) { 'FAIL' } elseif ($passed -eq 10) { 'PASS' } else { 'INCOMPLETE' }
    families_planned = $Plan.Count
    families_attempted = $Script:Results.Count
    families_passed = $passed
    families_failed = $failed
    halt_reason = $haltReason
    official_campaign_slots_consumed = 0
    official_run_directories_before = $officialBefore
    official_run_directories_after = $officialAfter
    ubuntu_baseline = $UbuntuSnapshot
    windows_baseline = $WindowsSnapshot
    official_runs_authorised = $false
    official_runs_authorisation_note = 'The official Ubuntu ransomware runs remain UNAUTHORISED. They may only be authorised by the owner after all ten preflights have passed.'
    results = $Script:Results
}
Write-Json $summaryJson $summary
Write-Host ''
Write-Host ('PREFLIGHT SUMMARY: ' + $passed + '/10 passed, ' + $failed + ' failed; official slots consumed=0; summary: ' + $summaryJson) -ForegroundColor $(if ($halted) { 'Red' } else { 'Green' })
if ($halted) { Write-Host ('OFFICIAL RUNS REMAIN UNAUTHORISED. Do not proceed. Halt reason: ' + $haltReason) -ForegroundColor Red; exit 1 }
if ($passed -ne 10) { Write-Host 'OFFICIAL RUNS REMAIN UNAUTHORISED: not all ten preflights passed.' -ForegroundColor Red; exit 1 }
Write-Host 'All ten preflights passed. The official runs may now be authorised by the owner (still NOT authorised by this script).' -ForegroundColor Green
exit 0
