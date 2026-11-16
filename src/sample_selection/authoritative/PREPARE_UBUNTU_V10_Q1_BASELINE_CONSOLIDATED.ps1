$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"
$ScriptDir = Join-Path $Root "01_SHARED\scripts\host\sample_selection"
$Vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
$UbuntuVmx = "D:\Ubuntu 24.04\Ubuntu.vmx"
$UbuntuVmDir = Split-Path -Parent $UbuntuVmx
$Bridge = Join-Path $Root "01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\UbuntuNativeBridge.ps1"

$FrozenRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH\FROZEN_SELECTION_20261110"
$FrozenManifest = Join-Path $FrozenRoot "UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv"

$GuestHelperHost = Join-Path $ScriptDir "UBUNTU_V10_Q1_PREP_GUEST.sh"
$GuestHelper = "/tmp/UBUNTU_V10_Q1_PREP_GUEST.sh"
$GuestResult = "/tmp/UBUNTU_V10_Q1_PREP_RESULT.txt"
$GuestCred = "/tmp/UBUNTU_V10_Q1_PREP.sudo"

$OutRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V10_Q1_PRELIVE_PREP_20261110"
$ArchiveRoot = Join-Path $Root "08_ARCHIVE\engineering_superseded\20261110_V10_PREP"

$ExistingSnapshot = "P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013"
$PlannedSnapshot = "P5G_V10_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261110"

$MinDFreeGiB = 8.0
$PreferredDFreeGiB = 10.0

New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
New-Item -ItemType Directory -Force -Path $ArchiveRoot | Out-Null

foreach($p in @($Vmrun,$UbuntuVmx,$Bridge,$FrozenManifest,$GuestHelperHost)){
    if(-not(Test-Path -LiteralPath $p -PathType Leaf)){ throw "Required file missing: $p" }
}

function Get-DriveFreeGiB([string]$DeviceId){
    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'"
    if(-not $d){ throw "Drive not found: $DeviceId" }
    return [math]::Round($d.FreeSpace / 1GB, 2)
}

function Get-RunningVmx {
    $out = @(& $Vmrun -T ws list 2>&1 | ForEach-Object { [string]$_ })
    if($LASTEXITCODE -ne 0){ throw "VMRUN_LIST_FAILED" }
    return @(
        $out | ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^[A-Za-z]:\\.*\.vmx$' }
    )
}

# ----------------------------------------------------------------------
# 1. Freeze/manifest validation
# ----------------------------------------------------------------------
$rows = @(Import-Csv -LiteralPath $FrozenManifest)
if($rows.Count -ne 19){ throw "Frozen V10 manifest must contain exactly 19 rows; found $($rows.Count)." }

$primary = @($rows | Where-Object { $_.role -ceq "PRIMARY" })
$reserve = @($rows | Where-Object { $_.role -ceq "RESERVE" })
if($primary.Count -ne 10){ throw "Expected 10 PRIMARY rows; found $($primary.Count)." }
if($reserve.Count -ne 9){ throw "Expected 9 RESERVE rows; found $($reserve.Count)." }

$families = @($rows | ForEach-Object { ([string]$_.family).Trim() })
$hashes = @($rows | ForEach-Object { ([string]$_.sha256).Trim().ToLowerInvariant() })

if(@($families | Sort-Object -Unique).Count -ne 19){ throw "Frozen manifest family uniqueness failed." }
if(@($hashes | Sort-Object -Unique).Count -ne 19){ throw "Frozen manifest SHA-256 uniqueness failed." }
foreach($h in $hashes){
    if($h -notmatch '^[0-9a-f]{64}$'){ throw "Invalid SHA-256 in frozen manifest: $h" }
}

$frozenManifestHash = (Get-FileHash -LiteralPath $FrozenManifest -Algorithm SHA256).Hash.ToLowerInvariant()
$bridgeHash = (Get-FileHash -LiteralPath $Bridge -Algorithm SHA256).Hash.ToLowerInvariant()
$guestHelperHash = (Get-FileHash -LiteralPath $GuestHelperHost -Algorithm SHA256).Hash.ToLowerInvariant()

# ----------------------------------------------------------------------
# 2. Archive only known failed/superseded engineering scripts.
#    Passed production/freeze scripts are NOT removed.
# ----------------------------------------------------------------------
$superseded = [ordered]@{
    "PREFLIGHT_UBUNTU_V10_STORAGE_AND_SNAPSHOT.ps1" = "FAILED_INTERACTIVE_CREDENTIAL_FLOW_SUPERSEDED_BY_NATIVE_VIX"
    "VERIFY_SESSION34_UBUNTU_10_VIA_VIX_HOST.ps1" = "FAILED_STAGE2_WRAPPER_SUPERSEDED"
    "VERIFY_SESSION34_UBUNTU_10_VIA_VIX_HOST_V2.ps1" = "SUPERSEDED_PERMISSION_FALSE_MISS"
    "VERIFY_SESSION34_UBUNTU_10_READONLY.py" = "SUPERSEDED_PERMISSION_FALSE_MISS"
    "RUN_SESSION34_UBUNTU_VERIFY_READONLY.sh" = "SUPERSEDED_PERMISSION_FALSE_MISS"
    "PRINT_QUALIFIED_NATIVE_VIX_CALL_CONTEXT.ps1" = "FAILED_WRONG_HARDCODED_CONTROLLER_PATH"
}

$archiveLedger = @()
foreach($name in $superseded.Keys){
    $src = Join-Path $ScriptDir $name
    if(Test-Path -LiteralPath $src -PathType Leaf){
        $hash = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant()
        $dst = Join-Path $ArchiveRoot $name
        if(Test-Path -LiteralPath $dst){
            $dstHash = (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash.ToLowerInvariant()
            if($dstHash -ne $hash){ throw "Archive collision with different hash: $dst" }
            Remove-Item -LiteralPath $src -Force
        } else {
            Move-Item -LiteralPath $src -Destination $dst
        }
        $archiveLedger += [pscustomobject]@{
            file_name=$name
            sha256=$hash
            disposition="ARCHIVED_NOT_RELEASE"
            reason=$superseded[$name]
            archive_path=$dst
        }
    }
}

$archiveCsv = Join-Path $OutRoot "SUPERSEDED_ENGINEERING_RETENTION_LEDGER.csv"
$archiveLedger | Export-Csv -LiteralPath $archiveCsv -NoTypeInformation -Encoding UTF8

# ----------------------------------------------------------------------
# 3. Pre-state
# ----------------------------------------------------------------------
$dBefore = Get-DriveFreeGiB "D:"
$cBefore = Get-DriveFreeGiB "C:"
$vmemBefore = @(
    Get-ChildItem -LiteralPath $UbuntuVmDir -File -Filter *.vmem -ErrorAction SilentlyContinue
)
$vmemBeforeBytes = [long](($vmemBefore | Measure-Object Length -Sum).Sum)
if($null -eq $vmemBeforeBytes){ $vmemBeforeBytes = 0 }

$running = @(Get-RunningVmx)
if(-not($running -contains $UbuntuVmx)){ throw "Ubuntu VM must be running for preparation." }
$other = @($running | Where-Object { $_ -cne $UbuntuVmx })
if($other.Count -gt 0){ throw "Another VM is running: $($other -join '; ')" }

$snapshots = @(& $Vmrun listSnapshots $UbuntuVmx 2>&1 | ForEach-Object { [string]$_ })
if($LASTEXITCODE -ne 0){ throw "Unable to list Ubuntu snapshots." }
$snapshotText = ($snapshots -join "`n")
$oldSnapshotPresent = $snapshotText -match [regex]::Escape($ExistingSnapshot)
$newSnapshotAlreadyExists = $snapshotText -match [regex]::Escape($PlannedSnapshot)
if(-not $oldSnapshotPresent){ throw "Existing frozen Ubuntu snapshot not found." }
if($newSnapshotAlreadyExists){ throw "Planned V10 snapshot name already exists; refuse ambiguous provenance." }

# ----------------------------------------------------------------------
# 4. Native-VIX guest preparation
# ----------------------------------------------------------------------
. $Bridge
$hostGuestReport = Join-Path $OutRoot "UBUNTU_V10_Q1_GUEST_PREP_RESULT.txt"

try{
    Start-UbuntuVM $Vmrun $UbuntuVmx

    Write-Host "Stage 1/5: Native-VIX V10 directory preparation..."
    Copy-ToUbuntuGuest $GuestHelperHost $GuestHelper
    New-UbuntuSudoCredentialFile $GuestCred | Out-Null

    $args = "$GuestHelper --cred=$GuestCred"
    $exit = Invoke-UbuntuGuestProgram "/bin/bash" $args 180
    if($exit -ne 0){ throw "Guest preparation exited with code $exit." }

    Copy-FromUbuntuGuest $GuestResult $hostGuestReport 120
    $guestText = Get-Content -LiteralPath $hostGuestReport -Raw

    if($guestText -notmatch 'STATUS=PASS_GUEST_PREPARATION'){ throw "Guest preparation did not report PASS." }
    if($guestText -notmatch 'TARGET_MODE=700'){ throw "V10 target directory mode drift." }
    if($guestText -notmatch 'TARGET_OWNER=root:root'){ throw "V10 target directory ownership drift." }

    Write-Host "Stage 2/5: cleanup temporary guest preparation artifacts..."
    try{ Invoke-UbuntuGuestProgram "/bin/rm" "-f $GuestHelper $GuestResult $GuestCred" 60 | Out-Null }catch{}

    Write-Host "Stage 3/5: clean Ubuntu power-off to reclaim runtime memory allocation..."
    Stop-UbuntuVM $Vmrun $UbuntuVmx
}
finally{
    try{ Close-UbuntuVix }catch{}
}

Start-Sleep -Seconds 5

# ----------------------------------------------------------------------
# 5. Post-poweroff storage/snapshot-chain audit
# ----------------------------------------------------------------------
Write-Host "Stage 4/5: post-poweroff storage audit..."
$runningAfter = @(Get-RunningVmx)
if($runningAfter -contains $UbuntuVmx){ throw "Ubuntu still running after clean power-off." }

$dAfter = Get-DriveFreeGiB "D:"
$cAfter = Get-DriveFreeGiB "C:"

$vmemAfter = @(
    Get-ChildItem -LiteralPath $UbuntuVmDir -File -Filter *.vmem -ErrorAction SilentlyContinue
)
$vmemAfterBytes = [long](($vmemAfter | Measure-Object Length -Sum).Sum)
if($null -eq $vmemAfterBytes){ $vmemAfterBytes = 0 }

# Never touch VMDK chain. Inventory only.
$vmdk = @(Get-ChildItem -LiteralPath $UbuntuVmDir -File -Filter *.vmdk -ErrorAction SilentlyContinue)
$vmdkBytes = [long](($vmdk | Measure-Object Length -Sum).Sum)
if($null -eq $vmdkBytes){ $vmdkBytes = 0 }

$largest = @(
    Get-ChildItem -LiteralPath $UbuntuVmDir -File -ErrorAction SilentlyContinue |
    Sort-Object Length -Descending |
    Select-Object -First 20 Name,Length,LastWriteTime
)
$largestCsv = Join-Path $OutRoot "UBUNTU_VM_TOP20_FILES.csv"
$largest | Export-Csv -LiteralPath $largestCsv -NoTypeInformation -Encoding UTF8

$spaceRecoveredGiB = [math]::Round($dAfter - $dBefore, 2)
$ready = ($dAfter -ge $MinDFreeGiB)
$preferred = ($dAfter -ge $PreferredDFreeGiB)

$status = if($ready){
    if($preferred){"PASS_READY_FOR_V10_MATERIALIZATION"}else{"PASS_MINIMUM_STORAGE_MARGIN"}
}else{
    "REVIEW_REQUIRED_LOW_D_SPACE"
}

Write-Host "Stage 5/5: write Q1 preparation receipt..."

$receipt = [ordered]@{
    schema_version="1.0"
    timestamp_utc=[DateTime]::UtcNow.ToString("o")
    status=$status

    frozen_manifest_path=$FrozenManifest
    frozen_manifest_sha256=$frozenManifestHash
    frozen_rows=19
    primary_rows=10
    reserve_rows=9
    unique_families=19
    unique_sha256=19

    native_vix_bridge_path=$Bridge
    native_vix_bridge_sha256=$bridgeHash
    guest_helper_sha256=$guestHelperHash

    old_snapshot=$ExistingSnapshot
    old_snapshot_present=$oldSnapshotPresent
    planned_snapshot=$PlannedSnapshot
    planned_snapshot_already_exists=$newSnapshotAlreadyExists

    guest_target="/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
    guest_target_prepared=$true
    guest_target_owner="root:root"
    guest_target_mode="700"
    old_r4_samples_preserved=$true
    old_r4_delete_rule="ONLY_AFTER_ALL_19_V10_SHA256_VERIFY"

    d_free_gib_before=$dBefore
    d_free_gib_after_poweroff=$dAfter
    d_space_recovered_gib=$spaceRecoveredGiB
    c_free_gib_before=$cBefore
    c_free_gib_after=$cAfter

    vmem_bytes_before=$vmemBeforeBytes
    vmem_bytes_after=$vmemAfterBytes
    vmdk_chain_bytes_inventory_only=$vmdkBytes
    vmdk_chain_modified=$false
    snapshots_modified=$false

    minimum_d_free_gib=$MinDFreeGiB
    preferred_d_free_gib=$PreferredDFreeGiB
    ready_for_materialization=$ready
    preferred_storage_margin_met=$preferred

    superseded_engineering_files_archived=$archiveLedger.Count
    superseded_ledger=$archiveCsv
    top20_vm_files=$largestCsv
    guest_report=$hostGuestReport

    official_run_slot_consumed=$false
}

$receiptPath = Join-Path $OutRoot "UBUNTU_V10_Q1_PRELIVE_PREPARATION_RECEIPT.json"
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

# Hash all preparation evidence.
$evidenceFiles = @($archiveCsv,$largestCsv,$hostGuestReport,$receiptPath) | Where-Object { Test-Path -LiteralPath $_ }
$hashRows = foreach($p in $evidenceFiles){
    [pscustomobject]@{
        file=(Split-Path -Leaf $p)
        bytes=(Get-Item -LiteralPath $p).Length
        sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$hashCsv = Join-Path $OutRoot "Q1_PREP_EVIDENCE_SHA256.csv"
$hashRows | Export-Csv -LiteralPath $hashCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "UBUNTU V10 Q1 PRE-LIVE PREPARATION: $status"
Write-Host "Frozen pool: 19 = 10 PRIMARY + 9 RESERVE"
Write-Host "Old snapshot preserved: $oldSnapshotPresent"
Write-Host "V10 target prepared: /opt/RansomLab/MalwareStaging/P5G/V10/Samples"
Write-Host "Old R4 samples preserved until 19/19 V10 hash verification."
Write-Host "D: free before power-off: $dBefore GiB"
Write-Host "D: free after power-off:  $dAfter GiB"
Write-Host "Recovered by clean power-off: $spaceRecoveredGiB GiB"
Write-Host "Remaining .vmem bytes: $vmemAfterBytes"
Write-Host "Snapshot/VMDK chain modified: False"
Write-Host "Superseded failed scripts archived: $($archiveLedger.Count)"
Write-Host "Receipt: $receiptPath"
Write-Host "Evidence hashes: $hashCsv"

if(-not $ready){ exit 2 }
exit 0
