$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"
$Vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
$UbuntuVmx = "D:\Ubuntu 24.04\Ubuntu.vmx"
$UbuntuVmDir = Split-Path -Parent $UbuntuVmx

$FrozenRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH\FROZEN_SELECTION_20261110"
$FrozenManifest = Join-Path $FrozenRoot "UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv"

$Bridge = Join-Path $Root "01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\UbuntuNativeBridge.ps1"
$GuestHelperHost = Join-Path $Root "01_SHARED\scripts\host\sample_selection\UBUNTU_V10_Q1_PREP_GUEST.sh"

$OutRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V10_Q1_PRELIVE_PREP_20261110"
$ArchiveRoot = Join-Path $Root "08_ARCHIVE\engineering_superseded\20261110_V10_PREP"

$GuestReport = Join-Path $OutRoot "UBUNTU_V10_Q1_GUEST_PREP_RESULT.txt"
$ArchiveLedger = Join-Path $OutRoot "SUPERSEDED_ENGINEERING_RETENTION_LEDGER.csv"

$ExistingSnapshot = "P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013"
$PlannedSnapshot = "P5G_V10_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261110"

$MinDFreeGiB = 8.0
$PreferredDFreeGiB = 10.0

function Get-DriveFreeGiB([string]$DeviceId){
    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'"
    if(-not $d){ throw "Drive not found: $DeviceId" }
    return [math]::Round($d.FreeSpace / 1GB, 2)
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

function Get-TotalLengthBytes([object[]]$Items){
    [long]$total = 0
    foreach($item in @($Items)){
        if($null -ne $item -and $null -ne $item.Length){
            $total += [long]$item.Length
        }
    }
    return $total
}

Write-Host "RESUMING UBUNTU V10 Q1 PREPARATION FROM POST-POWEROFF AUDIT"
Write-Host ""

foreach($p in @($Vmrun,$UbuntuVmx,$FrozenManifest,$Bridge,$GuestHelperHost,$GuestReport)){
    if(-not(Test-Path -LiteralPath $p -PathType Leaf)){
        throw "Required prior-stage artifact missing: $p"
    }
}

New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

# ----------------------------------------------------------------------
# Revalidate frozen scientific state.
# ----------------------------------------------------------------------
$rows = @(Import-Csv -LiteralPath $FrozenManifest)
if($rows.Count -ne 19){ throw "Frozen V10 manifest must contain 19 rows." }

$primary = @($rows | Where-Object { $_.role -ceq "PRIMARY" })
$reserve = @($rows | Where-Object { $_.role -ceq "RESERVE" })

if($primary.Count -ne 10){ throw "Expected 10 PRIMARY rows." }
if($reserve.Count -ne 9){ throw "Expected 9 RESERVE rows." }

$families = @($rows | ForEach-Object { ([string]$_.family).Trim() })
$hashes = @($rows | ForEach-Object { ([string]$_.sha256).Trim().ToLowerInvariant() })

if(@($families | Sort-Object -Unique).Count -ne 19){ throw "Family uniqueness failed." }
if(@($hashes | Sort-Object -Unique).Count -ne 19){ throw "SHA-256 uniqueness failed." }

foreach($h in $hashes){
    if($h -notmatch '^[0-9a-f]{64}$'){ throw "Invalid SHA-256 in frozen manifest: $h" }
}

$frozenManifestHash = (Get-FileHash -LiteralPath $FrozenManifest -Algorithm SHA256).Hash.ToLowerInvariant()
$bridgeHash = (Get-FileHash -LiteralPath $Bridge -Algorithm SHA256).Hash.ToLowerInvariant()
$guestHelperHash = (Get-FileHash -LiteralPath $GuestHelperHost -Algorithm SHA256).Hash.ToLowerInvariant()

# ----------------------------------------------------------------------
# Confirm prior guest preparation PASS.
# ----------------------------------------------------------------------
$guestText = Get-Content -LiteralPath $GuestReport -Raw
if($guestText -notmatch 'STATUS=PASS_GUEST_PREPARATION'){
    throw "Prior guest preparation did not report PASS."
}
if($guestText -notmatch 'TARGET_MODE=700'){
    throw "Prior V10 directory mode proof missing."
}
if($guestText -notmatch 'TARGET_OWNER=root:root'){
    throw "Prior V10 directory owner proof missing."
}
if($guestText -notmatch 'NOTE=OLD_R4_SAMPLES_PRESERVED_UNTIL_V10_19_HASH_VERIFIED'){
    throw "Old-sample preservation proof missing."
}

$oldCountMatch = [regex]::Match($guestText,'OLD_SAMPLE_COUNT=(\d+)')
$oldBytesMatch = [regex]::Match($guestText,'OLD_SAMPLE_BYTES=(\d+)')
$v10CountMatch = [regex]::Match($guestText,'V10_SAMPLE_COUNT=(\d+)')

$oldCount = if($oldCountMatch.Success){ [int]$oldCountMatch.Groups[1].Value } else { $null }
$oldBytes = if($oldBytesMatch.Success){ [long]$oldBytesMatch.Groups[1].Value } else { $null }
$v10Count = if($v10CountMatch.Success){ [int]$v10CountMatch.Groups[1].Value } else { $null }

# ----------------------------------------------------------------------
# Confirm Ubuntu is OFF and no unexpected VMs are running.
# ----------------------------------------------------------------------
$running = @(Get-RunningVmx)
if($running -contains $UbuntuVmx){
    throw "Ubuntu is running. It should already be OFF after successful Stage 3."
}

# ----------------------------------------------------------------------
# Snapshot inventory only.
# ----------------------------------------------------------------------
$snapshots = @(& $Vmrun listSnapshots $UbuntuVmx 2>&1 | ForEach-Object { [string]$_ })
if($LASTEXITCODE -ne 0){ throw "Unable to list Ubuntu snapshots." }

$snapshotText = ($snapshots -join "`n")
$oldSnapshotPresent = $snapshotText -match [regex]::Escape($ExistingSnapshot)
$newSnapshotAlreadyExists = $snapshotText -match [regex]::Escape($PlannedSnapshot)

if(-not $oldSnapshotPresent){
    throw "Existing frozen Ubuntu snapshot not found."
}
if($newSnapshotAlreadyExists){
    throw "Planned V10 snapshot name already exists; provenance review required."
}

# ----------------------------------------------------------------------
# Corrected post-poweroff storage audit.
# ----------------------------------------------------------------------
Write-Host "Stage 4/5: corrected post-poweroff storage audit..."

$dAfter = Get-DriveFreeGiB "D:"
$cAfter = Get-DriveFreeGiB "C:"

$vmemAfter = @(
    Get-ChildItem -LiteralPath $UbuntuVmDir -File -Filter *.vmem -ErrorAction SilentlyContinue
)
$vmemAfterBytes = Get-TotalLengthBytes $vmemAfter

$vmdk = @(
    Get-ChildItem -LiteralPath $UbuntuVmDir -File -Filter *.vmdk -ErrorAction SilentlyContinue
)
$vmdkBytes = Get-TotalLengthBytes $vmdk

$largest = @(
    Get-ChildItem -LiteralPath $UbuntuVmDir -File -ErrorAction SilentlyContinue |
    Sort-Object Length -Descending |
    Select-Object -First 20 Name,Length,LastWriteTime
)

$largestCsv = Join-Path $OutRoot "UBUNTU_VM_TOP20_FILES.csv"
$largest | Export-Csv -LiteralPath $largestCsv -NoTypeInformation -Encoding UTF8

# Since the failed V1 script crashed before recording the post-state,
# do not fabricate "before" or "recovered" numbers here.
$ready = ($dAfter -ge $MinDFreeGiB)
$preferred = ($dAfter -ge $PreferredDFreeGiB)

$status = if($ready){
    if($preferred){"PASS_READY_FOR_V10_MATERIALIZATION"}else{"PASS_MINIMUM_STORAGE_MARGIN"}
}else{
    "REVIEW_REQUIRED_LOW_D_SPACE"
}

# ----------------------------------------------------------------------
# Q1 receipt and evidence hashes.
# ----------------------------------------------------------------------
Write-Host "Stage 5/5: write corrected Q1 preparation receipt..."

$archivedCount = 0
if(Test-Path -LiteralPath $ArchiveLedger -PathType Leaf){
    $archivedCount = @(Import-Csv -LiteralPath $ArchiveLedger).Count
}

$receipt = [ordered]@{
    schema_version = "1.1"
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
    status = $status
    resumed_after_stage3 = $true
    v1_failure_reason = "POWERSHELL_STRICTMODE_EMPTY_MEASURE_OBJECT_SUM_PROPERTY"

    frozen_manifest_path = $FrozenManifest
    frozen_manifest_sha256 = $frozenManifestHash
    frozen_rows = 19
    primary_rows = 10
    reserve_rows = 9
    unique_families = 19
    unique_sha256 = 19

    native_vix_bridge_path = $Bridge
    native_vix_bridge_sha256 = $bridgeHash
    guest_helper_sha256 = $guestHelperHash

    old_snapshot = $ExistingSnapshot
    old_snapshot_present = $oldSnapshotPresent
    planned_snapshot = $PlannedSnapshot
    planned_snapshot_already_exists = $newSnapshotAlreadyExists

    guest_target = "/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
    guest_target_prepared = $true
    guest_target_owner = "root:root"
    guest_target_mode = "700"
    v10_sample_count_at_preparation = $v10Count

    old_r4_sample_root_preserved = $true
    old_r4_sample_count = $oldCount
    old_r4_sample_bytes = $oldBytes
    old_r4_delete_rule = "ONLY_AFTER_ALL_19_V10_SHA256_VERIFY"

    ubuntu_powered_off = $true
    d_free_gib_after_poweroff = $dAfter
    c_free_gib_after = $cAfter
    vmem_files_after_poweroff = @($vmemAfter).Count
    vmem_bytes_after_poweroff = $vmemAfterBytes

    vmdk_file_count = @($vmdk).Count
    vmdk_chain_bytes_inventory_only = $vmdkBytes
    vmdk_chain_modified = $false
    snapshots_modified = $false

    minimum_d_free_gib = $MinDFreeGiB
    preferred_d_free_gib = $PreferredDFreeGiB
    ready_for_materialization = $ready
    preferred_storage_margin_met = $preferred

    superseded_engineering_files_archived = $archivedCount
    superseded_ledger = if(Test-Path -LiteralPath $ArchiveLedger){$ArchiveLedger}else{$null}
    top20_vm_files = $largestCsv
    guest_report = $GuestReport

    official_run_slot_consumed = $false
}

$receiptPath = Join-Path $OutRoot "UBUNTU_V10_Q1_PRELIVE_PREPARATION_RECEIPT_V1_1.json"
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

$evidenceFiles = @(
    $FrozenManifest,
    $GuestReport,
    $largestCsv,
    $receiptPath
)
if(Test-Path -LiteralPath $ArchiveLedger -PathType Leaf){
    $evidenceFiles += $ArchiveLedger
}

$hashRows = foreach($p in $evidenceFiles){
    [pscustomobject]@{
        file = $p
        bytes = (Get-Item -LiteralPath $p).Length
        sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$hashCsv = Join-Path $OutRoot "Q1_PREP_EVIDENCE_SHA256_V1_1.csv"
$hashRows | Export-Csv -LiteralPath $hashCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "UBUNTU V10 Q1 PRE-LIVE PREPARATION: $status"
Write-Host "Frozen pool: 19 = 10 PRIMARY + 9 RESERVE"
Write-Host "Prior guest preparation proof: PASS"
Write-Host "Ubuntu powered off: True"
Write-Host "Existing frozen snapshot present: $oldSnapshotPresent"
Write-Host "Planned V10 snapshot already exists: $newSnapshotAlreadyExists"
Write-Host "Old R4 samples preserved: $oldCount"
Write-Host "V10 samples currently present: $v10Count"
Write-Host "D: free after power-off: $dAfter GiB"
Write-Host "Remaining .vmem files: $(@($vmemAfter).Count)"
Write-Host "Remaining .vmem bytes: $vmemAfterBytes"
Write-Host "VMDK/snapshot chain modified: False"
Write-Host "Receipt: $receiptPath"
Write-Host "Evidence hashes: $hashCsv"

if(-not $ready){ exit 2 }
exit 0
