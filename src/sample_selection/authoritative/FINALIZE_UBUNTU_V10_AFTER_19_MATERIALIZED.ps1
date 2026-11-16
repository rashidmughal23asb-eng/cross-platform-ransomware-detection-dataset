$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"
$ScriptDir = Join-Path $Root "01_SHARED\scripts\host\sample_selection"
$Vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
$UbuntuVmx = "D:\Ubuntu 24.04\Ubuntu.vmx"

$Bridge = Join-Path $Root "01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\UbuntuNativeBridge.ps1"
$FrozenManifest = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH\FROZEN_SELECTION_20261110\UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv"

$GuestHelperHost = Join-Path $ScriptDir "UBUNTU_V10_FINALIZE_GUEST.sh"
$GuestExpectedHost = Join-Path $ScriptDir "UBUNTU_V10_EXPECTED_SHA256.tsv"

$GuestHelper = "/tmp/UBUNTU_V10_FINALIZE_GUEST.sh"
$GuestExpected = "/tmp/UBUNTU_V10_EXPECTED_SHA256.tsv"
$GuestResult = "/tmp/UBUNTU_V10_FINALIZE_RESULT.txt"
$GuestCred = "/tmp/UBUNTU_V10_FINALIZE.sudo"

$OldSnapshot = "P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013"
$NewSnapshot = "P5G_V10_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261110"

$OutRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V10_POST_MATERIALIZATION_FINALIZE_20261110"
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

function Get-DriveFreeGiB([string]$DeviceId){
    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'"
    if(-not $d){ throw "Drive not found: $DeviceId" }
    return [math]::Round($d.FreeSpace / 1GB, 3)
}

function Get-RunningVmx {
    $out = @(& $Vmrun -T ws list 2>&1 | ForEach-Object { [string]$_ })
    if($LASTEXITCODE -ne 0){ throw "VMRUN_LIST_FAILED" }
    return @(
        $out |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^[A-Za-z]:\\.*\.vmx$' }
    )
}

foreach($p in @($Vmrun,$UbuntuVmx,$Bridge,$FrozenManifest,$GuestHelperHost)){
    if(-not(Test-Path -LiteralPath $p -PathType Leaf)){
        throw "Required file missing: $p"
    }
}

# ----------------------------------------------------------------------
# 1. Rebuild exact 19-row expected-hash TSV from frozen manifest.
# ----------------------------------------------------------------------
$rows = @(Import-Csv -LiteralPath $FrozenManifest)
if($rows.Count -ne 19){ throw "Frozen manifest row count is not 19." }

$primary = @($rows | Where-Object { $_.role -ceq "PRIMARY" })
$reserve = @($rows | Where-Object { $_.role -ceq "RESERVE" })
if($primary.Count -ne 10){ throw "Frozen PRIMARY count is not 10." }
if($reserve.Count -ne 9){ throw "Frozen RESERVE count is not 9." }

$lines = New-Object System.Collections.Generic.List[string]
foreach($r in ($rows | Sort-Object {[int]$_.frozen_rank})){
    $sha = ([string]$r.sha256).Trim().ToLowerInvariant()
    $family = ([string]$r.family).Trim()
    $role = ([string]$r.role).Trim()
    $rank = ([string]$r.frozen_rank).Trim()

    if($sha -notmatch '^[0-9a-f]{64}$'){ throw "Invalid frozen SHA-256: $sha" }
    if($family -match "`t|`r|`n"){ throw "Unsafe family text in manifest." }
    $lines.Add("$sha`t$family`t$role`t$rank")
}
[IO.File]::WriteAllLines($GuestExpectedHost,$lines,[Text.UTF8Encoding]::new($false))

$manifestHash = (Get-FileHash $FrozenManifest -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedHash = (Get-FileHash $GuestExpectedHost -Algorithm SHA256).Hash.ToLowerInvariant()
$bridgeHash = (Get-FileHash $Bridge -Algorithm SHA256).Hash.ToLowerInvariant()
$helperHash = (Get-FileHash $GuestHelperHost -Algorithm SHA256).Hash.ToLowerInvariant()

# ----------------------------------------------------------------------
# 2. Snapshot pre-state. Old snapshot must exist; new must not.
# ----------------------------------------------------------------------
$snapshotsBefore = @(& $Vmrun listSnapshots $UbuntuVmx 2>&1 | ForEach-Object { [string]$_ })
if($LASTEXITCODE -ne 0){ throw "Unable to list Ubuntu snapshots." }
$snapTextBefore = ($snapshotsBefore -join "`n")

$oldPresentBefore = $snapTextBefore -match [regex]::Escape($OldSnapshot)
$newPresentBefore = $snapTextBefore -match [regex]::Escape($NewSnapshot)

if(-not $oldPresentBefore){ throw "Old frozen snapshot missing; stop." }
if($newPresentBefore){ throw "New V10 snapshot already exists; refusing duplicate/ambiguous creation." }

$dBeforeVerify = Get-DriveFreeGiB "D:"

# ----------------------------------------------------------------------
# 3. Ubuntu must be the only running VM. If off, start through qualified bridge.
# ----------------------------------------------------------------------
$running = @(Get-RunningVmx)
$others = @($running | Where-Object { $_ -cne $UbuntuVmx })
if($others.Count -gt 0){ throw "Another VM is running: $($others -join '; ')" }

# Workstation GUI + stale-lock guard (shared with the population and repair steps).
. (Join-Path $ScriptDir 'UbuntuWorkstationLockGuard.ps1')
$lockInfo = Clear-UbuntuWorkstationLock -VmrunPath $Vmrun -Vmx $UbuntuVmx

. $Bridge

$HostResult = Join-Path $OutRoot "UBUNTU_V10_FINALIZE_RESULT.txt"

try {
    Write-Host "Stage 1/7: establish qualified Native-VIX Ubuntu session..."
    Start-UbuntuVM $Vmrun $UbuntuVmx

    Write-Host "Stage 2/7: transfer verification helper + frozen expected-hash manifest..."
    Copy-ToUbuntuGuest $GuestHelperHost $GuestHelper
    Copy-ToUbuntuGuest $GuestExpectedHost $GuestExpected
    New-UbuntuSudoCredentialFile $GuestCred | Out-Null

    Write-Host "Stage 3/7: verify 19/19 exact V10 SHA-256 identities and freeze permissions..."
    $args = "$GuestHelper --cred=$GuestCred --manifest=$GuestExpected"
    $exit = Invoke-UbuntuGuestProgram "/bin/bash" $args 600
    if($exit -ne 0){ throw "V10 finalization guest helper exited with code $exit." }

    Copy-FromUbuntuGuest $GuestResult $HostResult 180
    $guestText = Get-Content -LiteralPath $HostResult -Raw

    if($guestText -notmatch 'STATUS=PASS_ALL_19_HASH_VERIFIED_AND_PERMISSION_FROZEN'){
        throw "19/19 V10 guest verification did not PASS."
    }
    if($guestText -notmatch 'HASH_PASS=19'){ throw "Expected HASH_PASS=19 proof missing." }
    if($guestText -notmatch 'HASH_FAIL=0'){ throw "Expected HASH_FAIL=0 proof missing." }
    if($guestText -notmatch 'OLD_R4_SAMPLE_COUNT=10'){ throw "Old R4 10-sample preservation proof failed." }
    if($guestText -notmatch 'V10_ZERO_MODE_SAMPLE_COUNT=19'){ throw "V10 permission-freeze proof failed." }

    Write-Host "Stage 4/7: remove temporary verification artifacts..."
    try {
        Invoke-UbuntuGuestProgram "/bin/rm" "-f $GuestHelper $GuestExpected $GuestResult $GuestCred" 60 | Out-Null
    } catch {}

    Write-Host "Stage 5/7: clean power-off before snapshot..."
    try { Invoke-UbuntuGuestProgram "/bin/sync" "" 120 | Out-Null } catch {}
    Start-Sleep -Seconds 2
    Stop-UbuntuVM $Vmrun $UbuntuVmx
}
finally {
    try { Close-UbuntuVix } catch {}
}

Start-Sleep -Seconds 5

if((Get-RunningVmx) -contains $UbuntuVmx){ throw "Ubuntu still running before snapshot." }

$dBeforeSnapshot = Get-DriveFreeGiB "D:"

# ----------------------------------------------------------------------
# 4. Create powered-off snapshot. vmrun snapshot on an OFF VM does not
#    save guest RAM state, minimizing snapshot storage.
# ----------------------------------------------------------------------
Write-Host "Stage 6/7: create new powered-off V10 snapshot..."
& $Vmrun -T ws snapshot $UbuntuVmx $NewSnapshot 2>&1 | ForEach-Object { Write-Host $_ }
if($LASTEXITCODE -ne 0){ throw "V10 snapshot creation failed." }

Start-Sleep -Seconds 3

$snapshotsAfter = @(& $Vmrun listSnapshots $UbuntuVmx 2>&1 | ForEach-Object { [string]$_ })
if($LASTEXITCODE -ne 0){ throw "Unable to list snapshots after creation." }
$snapTextAfter = ($snapshotsAfter -join "`n")

$oldPresentAfter = $snapTextAfter -match [regex]::Escape($OldSnapshot)
$newPresentAfter = $snapTextAfter -match [regex]::Escape($NewSnapshot)

if(-not $oldPresentAfter){ throw "Old snapshot disappeared after V10 snapshot creation." }
if(-not $newPresentAfter){ throw "New V10 snapshot not visible after creation." }

$dAfterSnapshot = Get-DriveFreeGiB "D:"
$snapshotDeltaGiB = [math]::Round($dBeforeSnapshot - $dAfterSnapshot,3)
$snapshotDeltaMiB = [math]::Round(($dBeforeSnapshot - $dAfterSnapshot)*1024,1)

# ----------------------------------------------------------------------
# 5. Q1 evidence package.
# ----------------------------------------------------------------------
Write-Host "Stage 7/7: write Q1 post-materialization snapshot receipt..."

$receipt = [ordered]@{
    schema_version = "1.0"
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
    status = "PASS_V10_19_HASH_VERIFIED_NEW_SNAPSHOT_CREATED"

    frozen_manifest_path = $FrozenManifest
    frozen_manifest_sha256 = $manifestHash
    expected_hash_tsv_sha256 = $expectedHash
    native_vix_bridge_sha256 = $bridgeHash
    guest_helper_sha256 = $helperHash

    frozen_pool_count = 19
    primary_count = 10
    reserve_count = 9
    exact_sha256_verified = 19
    sha256_failures = 0

    old_r4_sample_count_preserved = 10
    old_snapshot = $OldSnapshot
    old_snapshot_present_before = $oldPresentBefore
    old_snapshot_present_after = $oldPresentAfter

    v10_guest_root = "/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
    v10_sample_count = 19
    v10_sample_permissions = "000"
    v10_directory_owner = "root:root"
    v10_directory_mode = "700"

    new_snapshot = $NewSnapshot
    new_snapshot_present_before = $newPresentBefore
    new_snapshot_present_after = $newPresentAfter
    snapshot_created_while_vm_off = $true
    guest_memory_snapshot_requested = $false

    d_free_gib_before_verification = $dBeforeVerify
    d_free_gib_before_snapshot = $dBeforeSnapshot
    d_free_gib_after_snapshot = $dAfterSnapshot
    observed_snapshot_storage_delta_gib = $snapshotDeltaGiB
    observed_snapshot_storage_delta_mib = $snapshotDeltaMiB

    vmdk_chain_manually_modified = $false
    old_baseline_deleted = $false
    official_run_slot_consumed = $false

    guest_verification_report = $HostResult
}

$receiptPath = Join-Path $OutRoot "UBUNTU_V10_POST_MATERIALIZATION_SNAPSHOT_RECEIPT.json"
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

$snapshotListPath = Join-Path $OutRoot "UBUNTU_SNAPSHOT_LIST_AFTER.txt"
$snapshotsAfter | Set-Content -LiteralPath $snapshotListPath -Encoding UTF8

$hashFiles = @(
    $FrozenManifest,
    $GuestExpectedHost,
    $GuestHelperHost,
    $HostResult,
    $snapshotListPath,
    $receiptPath
)

$hashRows = foreach($p in $hashFiles){
    [pscustomobject]@{
        file = $p
        bytes = (Get-Item -LiteralPath $p).Length
        sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$hashCsv = Join-Path $OutRoot "UBUNTU_V10_POST_MATERIALIZATION_EVIDENCE_SHA256.csv"
$hashRows | Export-Csv -LiteralPath $hashCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "UBUNTU V10 POST-MATERIALIZATION FINALIZATION: PASS"
Write-Host "Fresh V10 samples verified: 19/19"
Write-Host "Old R4 samples preserved: 10/10"
Write-Host "Old snapshot preserved: $oldPresentAfter"
Write-Host "New snapshot created: $newPresentAfter"
Write-Host "Snapshot created with Ubuntu OFF: True"
Write-Host "D: free before snapshot: $dBeforeSnapshot GiB"
Write-Host "D: free after snapshot:  $dAfterSnapshot GiB"
Write-Host "Observed new snapshot delta: $snapshotDeltaMiB MiB"
Write-Host "Receipt: $receiptPath"
Write-Host "Evidence hashes: $hashCsv"
