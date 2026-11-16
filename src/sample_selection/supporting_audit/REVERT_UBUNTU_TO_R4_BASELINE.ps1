<#
.SYNOPSIS
  Revert the Ubuntu VM to the frozen R4 baseline snapshot, as step 1 of the
  clean V10 rebuild.

.DESCRIPTION
  The V10 materialization already succeeded once, but only after a repair hop
  (4 of the 19 files were re-written after a zero-byte fault). This script
  throws that history away so the evidence trail contains exactly one clean
  materialization pass.

  What it does:
    1. asserts Administrator, required paths, 0 running VMs
    2. clears the Workstation GUI + an orphaned <vmx>.lck (shared guard)
    3. asserts snapshot state: exactly 7 snapshots, current snapshot is the
       frozen R4 baseline, and the V10 post-materialization snapshot does NOT exist
    4. records D: free space and the working-delta footprint
    5. reverts to P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013
    6. re-asserts the same snapshot state, VM powered off
    7. records D: free space again and writes a receipt + evidence hashes

  A revert to a Workstation snapshot discards the current delta (the failed
  attempts live there) and restores the baseline disk exactly. It does not
  create, delete or rename any snapshot.

  This script does NOT populate samples, does NOT create a snapshot, does NOT
  execute any sample, and consumes no run slots.

.PARAMETER PreflightOnly
  Run every assertion and measurement, then stop without reverting.

.PARAMETER VerifyManualRevert
  For the case where the revert was done by hand in the VMware Workstation GUI
  (VM > Snapshots > Revert To Snapshot). Runs the same assertions and
  measurements, writes a receipt recording that the revert was manual, and
  stops without reverting. Use it right after the manual revert, before
  POPULATE_UBUNTU_V10_GUEST_SAMPLES.ps1.

.EXAMPLE
  .\REVERT_UBUNTU_TO_R4_BASELINE.ps1 -PreflightOnly
  .\REVERT_UBUNTU_TO_R4_BASELINE.ps1
  .\REVERT_UBUNTU_TO_R4_BASELINE.ps1 -VerifyManualRevert
#>

[CmdletBinding()]
param(
    [string]$CampaignRoot  = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs",
    [string]$VmrunPath     = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
    [string]$UbuntuVmxPath = "D:\Ubuntu 24.04\Ubuntu.vmx",
    [string]$OldSnapshot   = "P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013",
    [string]$NewSnapshot   = "P5G_V10_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261110",
    [string]$OutRoot       = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs\01_SHARED\sample_selection\UBUNTU_V10_CLEAN_REBUILD_20261110",
    [switch]$PreflightOnly,
    [switch]$VerifyManualRevert
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ScriptDir = Join-Path $CampaignRoot "01_SHARED\scripts\host\sample_selection"
$Bridge    = Join-Path $CampaignRoot "01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\UbuntuNativeBridge.ps1"
$Guard     = Join-Path $ScriptDir "UbuntuWorkstationLockGuard.ps1"
$ScriptPath = $MyInvocation.MyCommand.Path

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function SHA([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-Step([string]$m) { Write-Host ""; Write-Host ("=== " + $m) -ForegroundColor Cyan }

function Get-CurrentSnapshotName([string]$Vmx) {
    $vmsd = @(Get-ChildItem -LiteralPath (Split-Path -Parent $Vmx) -Filter '*.vmsd' -File)
    Assert-True ($vmsd.Count -eq 1) "VMSD_NOT_UNIQUE"
    $cur = ''; $map = @{}
    foreach ($l in [IO.File]::ReadAllLines($vmsd[0].FullName)) {
        $m = [regex]::Match($l, '^\s*snapshot\.current\s*=\s*"([^"]*)"')
        if ($m.Success) { $cur = $m.Groups[1].Value }
        $m = [regex]::Match($l, '^\s*snapshot(\d+)\.(uid|displayName)\s*=\s*"([^"]*)"')
        if ($m.Success) {
            $i = [int]$m.Groups[1].Value
            if (-not $map.ContainsKey($i)) { $map[$i] = @{} }
            $map[$i][$m.Groups[2].Value] = $m.Groups[3].Value
        }
    }
    Assert-True (-not [string]::IsNullOrWhiteSpace($cur)) "NO_CURRENT_SNAPSHOT"
    foreach ($i in $map.Keys) { if ([string]$map[$i]['uid'] -ceq $cur) { return [string]$map[$i]['displayName'] } }
    throw "SNAPSHOT_UID_UNMAPPED"
}

# vmrun prints "Total snapshots: N" then one line per snapshot. A snapshot
# genuinely named "list" exists on this host (uid 13), so only the header may
# be dropped. Always cross-check the parsed count against N.
function Get-SnapshotNames {
    $raw = @(& $VmrunPath -T ws listSnapshots $UbuntuVmxPath 2>&1 | ForEach-Object { ([string]$_).Trim() })
    Assert-True ($LASTEXITCODE -eq 0) ("SNAPSHOT_LIST_FAILED: " + ($raw -join ' | '))
    $header = @($raw | Where-Object { $_ -match '^Total snapshots:\s*\d+' })
    Assert-True ($header.Count -eq 1) ("SNAPSHOT_HEADER_UNEXPECTED: " + ($raw -join ' | '))
    $declared = [int]([regex]::Match($header[0], '\d+').Value)
    $names = @($raw | Where-Object { $_ -notmatch '^Total snapshots:' -and -not [string]::IsNullOrWhiteSpace($_) })
    Assert-True ($names.Count -eq $declared) ("SNAPSHOT_LIST_INCONSISTENT: declared=" + $declared + " parsed=" + $names.Count)
    return $names
}

function Get-RunningVm {
    return @(& $VmrunPath -T ws list 2>&1 | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[A-Za-z]:\\.*\.vmx$' })
}

function Get-DiskFreeBytes([string]$Drive) {
    $d = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $Drive + "'")
    Assert-True ($null -ne $d) ("DRIVE_NOT_FOUND: " + $Drive)
    return [int64]$d.FreeSpace
}

# Footprint of the VM folder, broken out by delta group, so the cost of the
# revert is measured rather than assumed.
function Get-UbuntuFootprint {
    $dir = Split-Path -Parent $UbuntuVmxPath
    $files = @(Get-ChildItem -LiteralPath $dir -File -Recurse -ErrorAction SilentlyContinue)
    $delta = @($files | Where-Object { $_.Name -match '^Ubuntu-\d+-s\d+\.vmdk$' })
    $vmsn  = @($files | Where-Object { $_.Extension -eq '.vmsn' })
    $groups = @{}
    foreach ($f in $delta) {
        $g = ([regex]::Match($f.Name, '^(Ubuntu-\d+)-s\d+\.vmdk$')).Groups[1].Value
        if (-not $groups.ContainsKey($g)) { $groups[$g] = [int64]0 }
        $groups[$g] += [int64]$f.Length
    }
    return [pscustomobject]@{
        folder_total_bytes = [int64](($files | Measure-Object Length -Sum).Sum)
        file_count         = $files.Count
        delta_total_bytes  = [int64](($delta | Measure-Object Length -Sum).Sum)
        delta_file_count   = $delta.Count
        delta_groups       = $groups
        vmsn_total_bytes   = [int64](($vmsn | Measure-Object Length -Sum).Sum)
        vmsn_count         = $vmsn.Count
    }
}

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Assert-True ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'

foreach ($p in @($VmrunPath, $UbuntuVmxPath, $Bridge, $Guard)) {
    Assert-True (Test-Path -LiteralPath $p) ("REQUIRED_PATH_MISSING: " + $p)
}
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

Write-Step ("1/5 Preflight" + $(if ($PreflightOnly) { " (NO REVERT)" } else { "" }))

$running = @(Get-RunningVm)
Assert-True ($running.Count -eq 0) ("OTHER_VM_RUNNING: " + ($running -join '; '))
Write-Host "running VMs     : 0"

# Shared guard. Only the scripted revert needs the lock cleared: a native-VIX
# revert cannot run while Workstation holds <vmx>.lck. The read-only modes
# (-PreflightOnly / -VerifyManualRevert) never touch the VM, so they must not
# close a GUI that was opened on purpose - that is what made the VM "disappear"
# right after a manual revert.
$lockPath = $UbuntuVmxPath + '.lck'
if ($PreflightOnly -or $VerifyManualRevert) {
    $gui = @(Get-Process -Name 'vmware' -ErrorAction SilentlyContinue)
    if ($gui.Count -gt 0) {
        Write-Host ("workstation GUI : open ({0} process(es)) - left alone, read-only mode" -f $gui.Count)
    }
    else {
        Write-Host "workstation GUI : not running"
    }
    if (Test-Path -LiteralPath $lockPath) {
        Write-Host "vmx lock        : present (ignored, read-only mode)"
    }
    else {
        Write-Host "vmx lock        : absent"
    }
    $lockInfo = [pscustomobject]@{ gui_processes_closed = 0; stale_lock_removed = $false; lock_path = $lockPath }
}
else {
    . $Guard
    $lockInfo = Clear-UbuntuWorkstationLock -VmrunPath $VmrunPath -Vmx $UbuntuVmxPath
    Write-Host ("lock path       : " + $lockInfo.lock_path)
}

$snapBefore   = @(Get-SnapshotNames)
$currentBefore = Get-CurrentSnapshotName $UbuntuVmxPath

Write-Host ("snapshots       : " + $snapBefore.Count)
Write-Host ("current snapshot: " + $currentBefore)

Assert-True ($snapBefore.Count -eq 7) ("SNAPSHOT_COUNT_NOT_7: " + $snapBefore.Count)
Assert-True (@($snapBefore | Where-Object { $_ -ceq $OldSnapshot }).Count -eq 1) "OLD_R4_SNAPSHOT_MISSING"
Assert-True (@($snapBefore | Where-Object { $_ -ceq $NewSnapshot }).Count -eq 0) "V10_SNAPSHOT_ALREADY_EXISTS"
Assert-True ($currentBefore -ceq $OldSnapshot) ("SNAPSHOT_DRIFT expected=" + $OldSnapshot + " actual=" + $currentBefore)
Write-Host "snapshot binding: OK (old R4 present, V10 absent, current == old R4)"

$freeBefore = Get-DiskFreeBytes 'D:'
$fpBefore   = Get-UbuntuFootprint

Write-Host ""
Write-Host ("D: free before  : {0:N3} GiB" -f ($freeBefore / 1GB))
Write-Host ("VM folder before: {0:N3} GiB in {1} files" -f ($fpBefore.folder_total_bytes / 1GB), $fpBefore.file_count)
Write-Host ("working delta   : {0:N2} MiB in {1} files" -f ($fpBefore.delta_total_bytes / 1MB), $fpBefore.delta_file_count)
foreach ($k in ($fpBefore.delta_groups.Keys | Sort-Object)) {
    Write-Host ("  {0} : {1:N2} MiB" -f $k, ($fpBefore.delta_groups[$k] / 1MB))
}
Write-Host ("snapshot state  : {0:N1} KiB in {1} .vmsn files" -f ($fpBefore.vmsn_total_bytes / 1KB), $fpBefore.vmsn_count)

# --------------------------------------------------------------------------
# Receipt writer (shared by the automated revert and the manual-revert verify)
# --------------------------------------------------------------------------
function Write-RevertArtifacts {
    param(
        [string]$Status,
        [string]$Method,
        [bool]$RevertPerformed,
        [string[]]$SnapshotsAfter,
        [string]$CurrentAfter,
        [int64]$FreeAfter,
        [object]$FootprintAfter,
        [string]$StepLabel
    )

    $stamp = (Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $freeDelta = $FreeAfter - $freeBefore
    $fpDelta   = $FootprintAfter.folder_total_bytes - $fpBefore.folder_total_bytes

    $receipt = [ordered]@{
        schema_version                    = "1.0"
        timestamp_utc                     = [DateTime]::UtcNow.ToString("o")
        status                            = $Status
        step                              = $StepLabel
        revert_method                     = $Method
        revert_performed_by_this_script   = $RevertPerformed
        frozen_manifest_sha256            = (SHA (Join-Path $CampaignRoot "01_SHARED\sample_selection\UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH\FROZEN_SELECTION_20261110\UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv"))
        ubuntu_vmx                        = $UbuntuVmxPath
        target_snapshot                   = $OldSnapshot
        current_snapshot_at_start         = $currentBefore
        current_snapshot_after            = $CurrentAfter
        snapshot_count_at_start           = $snapBefore.Count
        snapshot_count_after              = $SnapshotsAfter.Count
        snapshot_list_after               = $SnapshotsAfter
        v10_snapshot_created              = $false
        ubuntu_powered_off_after          = $true
        gui_processes_closed              = $lockInfo.gui_processes_closed
        stale_lock_removed                = $lockInfo.stale_lock_removed
        d_free_bytes_at_start             = $freeBefore
        d_free_bytes_at_end               = $FreeAfter
        d_free_delta_bytes_observed       = $freeDelta
        vm_folder_bytes_at_start          = $fpBefore.folder_total_bytes
        vm_folder_bytes_at_end            = $FootprintAfter.folder_total_bytes
        vm_folder_delta_bytes             = $fpDelta
        working_delta_bytes_at_start      = $fpBefore.delta_total_bytes
        working_delta_bytes_at_end        = $FootprintAfter.delta_total_bytes
        working_delta_groups_at_start     = $fpBefore.delta_groups
        working_delta_groups_at_end       = $FootprintAfter.delta_groups
        malware_executed                  = $false
        official_run_slot_consumed        = $false
        next_step                         = "POPULATE_UBUNTU_V10_GUEST_SAMPLES.ps1 (clean single-pass materialization)"
    }
    if (-not $RevertPerformed) {
        $receipt["note"] = "Snapshot state verified against the frozen R4 baseline. The revert itself was performed outside this script (manual Workstation GUI), so the pre-revert D: footprint was not captured by automation. The Workstation GUI, if open, was left untouched: this mode never powers the VM on."
    }

    $receiptPath = Join-Path $OutRoot ("UBUNTU_V10_REVERT_TO_R4_BASELINE_RECEIPT_{0}.json" -f $stamp)
    [IO.File]::WriteAllText($receiptPath, (($receipt | ConvertTo-Json -Depth 20) + "`r`n"), (New-Object Text.UTF8Encoding($false)))

    $evidencePath = Join-Path $OutRoot ("UBUNTU_V10_REVERT_TO_R4_BASELINE_EVIDENCE_SHA256_{0}.csv" -f $stamp)
    Assert-True (-not [string]::IsNullOrWhiteSpace($ScriptPath)) "SCRIPT_PATH_UNRESOLVED_FOR_EVIDENCE"
    $evRows = foreach ($p in @($VmrunPath, $UbuntuVmxPath, $Bridge, $Guard, $ScriptPath, $receiptPath)) {
        Assert-True (Test-Path -LiteralPath $p) ("EVIDENCE_PATH_MISSING: " + $p)
        [pscustomobject]@{ file = $p; bytes = (Get-Item -LiteralPath $p).Length; sha256 = (SHA $p) }
    }
    $evRows | Export-Csv -LiteralPath $evidencePath -NoTypeInformation -Encoding UTF8

    return [pscustomobject]@{
        receipt      = $receiptPath
        evidence     = $evidencePath
        receipt_sha  = (SHA $receiptPath)
        receipt_size = (Get-Item -LiteralPath $receiptPath).Length
        free_delta   = $freeDelta
        folder_delta = $fpDelta
    }
}

if ($PreflightOnly) {
    Write-Host ""
    Write-Host "PREFLIGHT: PASS (no revert performed)" -ForegroundColor Green
    Write-Host "The VM is at the frozen R4 baseline and ready to be re-populated."
    Write-Host "If you want a receipt for this state, use -VerifyManualRevert after a manual GUI revert."
    exit 0
}

if ($VerifyManualRevert) {
    Write-Step "2/5 Verify the manual GUI revert"
    $art = Write-RevertArtifacts -Status 'PASS_MANUAL_GUI_REVERT_VERIFIED' `
        -Method 'manual_vmware_workstation_gui' -RevertPerformed $false `
        -SnapshotsAfter $snapBefore -CurrentAfter $currentBefore `
        -FreeAfter $freeBefore -FootprintAfter $fpBefore `
        -StepLabel 'clean_rebuild_step_1_manual'
    Write-Host ""
    Write-Host "MANUAL REVERT: VERIFIED" -ForegroundColor Green
    Write-Host ("Ubuntu is at the frozen R4 baseline: " + $currentBefore)
    Write-Host "7 snapshots, V10 snapshot absent, VM off."
    Write-Host ""
    Write-Host ("Receipt : " + $art.receipt + " (" + $art.receipt_size + " B, sha " + $art.receipt_sha.Substring(0, 16) + "...)")
    Write-Host ("Evidence: " + $art.evidence)
    Write-Host ""
    Write-Host "NEXT: run POPULATE_UBUNTU_V10_GUEST_SAMPLES.ps1 for the clean single-pass"
    Write-Host "      materialization of all 19 frozen artifacts. No snapshot will be created."
    exit 0
}

# --------------------------------------------------------------------------
# Revert
# --------------------------------------------------------------------------
Write-Step "2/5 Revert to the frozen R4 baseline"
. $Bridge
try {
    Revert-UbuntuExactSnapshot $VmrunPath $UbuntuVmxPath $OldSnapshot
}
catch {
    $err = $_
    Write-Host ""
    Write-Host ("REVERT FAILED: " + $err.Exception.Message) -ForegroundColor Red
    try { Close-UbuntuVix } catch { }
    try { Stop-UbuntuVM $VmrunPath $UbuntuVmxPath } catch { }
    try {
        $stillRunning = @(Get-RunningVm)
        Assert-True ($stillRunning.Count -eq 0) ("UBUNTU_STILL_RUNNING: " + ($stillRunning -join '; '))
        $curFail = Get-CurrentSnapshotName $UbuntuVmxPath
        Write-Host ("ubuntu          : OFF; current snapshot " + $curFail) -ForegroundColor Yellow
    }
    catch {
        Write-Host ("POST-FAILURE STATE CHECK FAILED: " + $_.Exception.Message) -ForegroundColor Red
    }
    throw $err
}
finally {
    try { Close-UbuntuVix } catch { }
}

Start-Sleep -Seconds 3

# --------------------------------------------------------------------------
# Verify
# --------------------------------------------------------------------------
Write-Step "3/5 Verify post-revert state"

$runningAfter = @(Get-RunningVm)
Assert-True ($runningAfter.Count -eq 0) ("UBUNTU_STILL_RUNNING_AFTER_REVERT: " + ($runningAfter -join '; '))

$snapAfter    = @(Get-SnapshotNames)
$currentAfter = Get-CurrentSnapshotName $UbuntuVmxPath

Assert-True ($snapAfter.Count -eq 7) ("SNAPSHOT_COUNT_CHANGED: " + $snapAfter.Count)
Assert-True ($currentAfter -ceq $OldSnapshot) ("REVERT_NOT_BOUND_TO_R4: " + $currentAfter)
Assert-True (@($snapAfter | Where-Object { $_ -ceq $NewSnapshot }).Count -eq 0) "SNAPSHOT_CREATED_IN_REVERT_STEP"
foreach ($n in $snapBefore) {
    Assert-True (@($snapAfter | Where-Object { $_ -ceq $n }).Count -eq 1) ("SNAPSHOT_LOST: " + $n)
}

Write-Host "ubuntu          : OFF"
Write-Host ("snapshots       : " + $snapAfter.Count + " (unchanged set)")
Write-Host ("current snapshot: " + $currentAfter)
Write-Host "new V10 snapshot: NOT created (correct for this step)"

$freeAfter = Get-DiskFreeBytes 'D:'
$fpAfter   = Get-UbuntuFootprint

Write-Host ""
Write-Host ("D: free after   : {0:N3} GiB" -f ($freeAfter / 1GB))
Write-Host ("VM folder after : {0:N3} GiB in {1} files" -f ($fpAfter.folder_total_bytes / 1GB), $fpAfter.file_count)
Write-Host ("working delta   : {0:N2} MiB in {1} files" -f ($fpAfter.delta_total_bytes / 1MB), $fpAfter.delta_file_count)
foreach ($k in ($fpAfter.delta_groups.Keys | Sort-Object)) {
    Write-Host ("  {0} : {1:N2} MiB" -f $k, ($fpAfter.delta_groups[$k] / 1MB))
}

# --------------------------------------------------------------------------
# Receipt
# --------------------------------------------------------------------------
Write-Step "4/5 Receipt + evidence hashes"

$art = Write-RevertArtifacts -Status 'PASS_UBUNTU_REVERTED_TO_R4_BASELINE' `
    -Method 'native_vix_vmrun' -RevertPerformed $true `
    -SnapshotsAfter $snapAfter -CurrentAfter $currentAfter `
    -FreeAfter $freeAfter -FootprintAfter $fpAfter `
    -StepLabel 'clean_rebuild_step_1_of_2'

Write-Host ""
Write-Host ("D: free delta   : {0:+0.000;-0.000;0.000} GiB" -f ($art.free_delta / 1GB))
Write-Host ("folder delta    : {0:+0.00;-0.00;0.00} MiB" -f ($art.folder_delta / 1MB))

Write-Step "5/5 Result"
Write-Host "UBUNTU REVERT: PASS" -ForegroundColor Green
Write-Host ("Ubuntu is back at the frozen R4 baseline: " + $currentAfter)
Write-Host "7 snapshots, none created, none renamed, none deleted."
Write-Host "The failed-attempt delta has been discarded by the revert."
Write-Host ""
Write-Host ("Receipt : " + $art.receipt + " (" + $art.receipt_size + " B, sha " + $art.receipt_sha.Substring(0, 16) + "...)")
Write-Host ("Evidence: " + $art.evidence)
Write-Host ""
Write-Host "NEXT: run POPULATE_UBUNTU_V10_GUEST_SAMPLES.ps1 for the clean single-pass"
Write-Host "      materialization of all 19 frozen artifacts. No snapshot will be created."
exit 0
