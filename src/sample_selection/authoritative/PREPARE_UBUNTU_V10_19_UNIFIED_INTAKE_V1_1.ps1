$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"

$FrozenManifest = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH\FROZEN_SELECTION_20261110\UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv"

$OutRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V10_MATERIALIZATION_INTAKE_20261110"
$UnifiedIntake = Join-Path $OutRoot "host_archive_intake_all19"
$EvidenceRoot = Join-Path $OutRoot "evidence"

New-Item -ItemType Directory -Force -Path $OutRoot,$UnifiedIntake,$EvidenceRoot | Out-Null

if(-not(Test-Path -LiteralPath $FrozenManifest -PathType Leaf)){
    throw "Frozen V10 manifest missing: $FrozenManifest"
}

$rows = @(Import-Csv -LiteralPath $FrozenManifest)
if($rows.Count -ne 19){ throw "Expected exactly 19 frozen V10 rows; found $($rows.Count)." }

$primary = @($rows | Where-Object { $_.role -ceq "PRIMARY" })
$reserve = @($rows | Where-Object { $_.role -ceq "RESERVE" })

if($primary.Count -ne 10){ throw "Expected 10 PRIMARY rows; found $($primary.Count)." }
if($reserve.Count -ne 9){ throw "Expected 9 RESERVE rows; found $($reserve.Count)." }

$families = @()
$hashes = @()
$ledger = @()

foreach($r in ($rows | Sort-Object {[int]$_.frozen_rank})){
    $rank = [int]$r.frozen_rank
    $role = ([string]$r.role).Trim()
    $family = ([string]$r.family).Trim()
    $sha = ([string]$r.sha256).Trim().ToLowerInvariant()

    if($sha -notmatch '^[0-9a-f]{64}$'){
        throw "Invalid SHA-256 at rank ${rank}: $sha"
    }
    if([string]::IsNullOrWhiteSpace($family)){
        throw "Missing family at rank ${rank}."
    }

    $families += $family
    $hashes += $sha

    $ledger += [pscustomobject]@{
        frozen_rank = $rank
        role = $role
        family = $family
        expected_sha256 = $sha
        host_intake_root = $UnifiedIntake
        host_intake_status = "PENDING"
        guest_target_path = "/opt/RansomLab/MalwareStaging/P5G/V10/Samples/$sha.sample"
        materialization_status = "PENDING"
        sha256_verification_status = "PENDING"
        qualification_status = "PENDING"
        promotion_rule = if($role -eq "PRIMARY"){
            "KEEP_IF_QUALIFIED_ELSE_PROMOTE_NEXT_FROZEN_RESERVE"
        } else {
            "PROMOTE_ONLY_IN_FROZEN_RANK_ORDER"
        }
        reranking_after_outcomes = "NOT_ALLOWED"
        official_run_slot_consumed = "FALSE"
    }
}

if(@($families | Sort-Object -Unique).Count -ne 19){ throw "Frozen family uniqueness failed." }
if(@($hashes | Sort-Object -Unique).Count -ne 19){ throw "Frozen SHA-256 uniqueness failed." }

# Clean up only empty per-family intake directories from the earlier bookkeeping design.
$removedEmpty = @()
$preservedNonEmpty = @()

$oldPerFamilyRoot = Join-Path $OutRoot "host_archive_intake"
if(Test-Path -LiteralPath $oldPerFamilyRoot -PathType Container){
    Get-ChildItem -LiteralPath $oldPerFamilyRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $items = @(Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue)
        if($items.Count -eq 0){
            Remove-Item -LiteralPath $_.FullName -Force
            $removedEmpty += $_.FullName
        } else {
            $preservedNonEmpty += $_.FullName
        }
    }

    $remaining = @(Get-ChildItem -LiteralPath $oldPerFamilyRoot -Force -ErrorAction SilentlyContinue)
    if($remaining.Count -eq 0){
        Remove-Item -LiteralPath $oldPerFamilyRoot -Force
    }
}

$ledgerPath = Join-Path $EvidenceRoot "UBUNTU_V10_19_UNIFIED_MATERIALIZATION_LEDGER.csv"
$ledger | Export-Csv -LiteralPath $ledgerPath -NoTypeInformation -Encoding UTF8

$cleanupLedger = [ordered]@{
    removed_empty_legacy_intake_directories = $removedEmpty
    preserved_nonempty_legacy_intake_directories = $preservedNonEmpty
}
$cleanupPath = Join-Path $EvidenceRoot "UNIFIED_INTAKE_CLEANUP_LEDGER.json"
$cleanupLedger | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $cleanupPath -Encoding UTF8

$manifestHash = (Get-FileHash -LiteralPath $FrozenManifest -Algorithm SHA256).Hash.ToLowerInvariant()
$ledgerHash = (Get-FileHash -LiteralPath $ledgerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$cleanupHash = (Get-FileHash -LiteralPath $cleanupPath -Algorithm SHA256).Hash.ToLowerInvariant()

$receipt = [ordered]@{
    schema_version = "1.1"
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
    status = "PASS_V10_UNIFIED_MATERIALIZATION_INTAKE_PREPARED"

    frozen_manifest_path = $FrozenManifest
    frozen_manifest_sha256 = $manifestHash

    frozen_pool_count = 19
    primary_count = 10
    reserve_count = 9
    unique_families = 19
    unique_sha256 = 19

    host_intake_root = $UnifiedIntake
    host_intake_layout = "SINGLE_DIRECTORY_ALL_19"
    guest_materialization_root = "/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
    guest_materialization_layout = "SINGLE_DIRECTORY_ALL_19"

    ledger_path = $ledgerPath
    ledger_sha256 = $ledgerHash
    cleanup_ledger_path = $cleanupPath
    cleanup_ledger_sha256 = $cleanupHash

    removed_empty_legacy_intake_directories = $removedEmpty.Count
    preserved_nonempty_legacy_intake_directories = $preservedNonEmpty.Count

    old_r4_baseline_preservation = "REQUIRED"
    old_r4_snapshot_preservation = "REQUIRED"
    new_snapshot_name = "P5G_V10_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261110"

    reranking_after_outcomes = $false
    reserve_promotion_order_frozen = $true
    official_run_slots_consumed = 0
}

$receiptPath = Join-Path $EvidenceRoot "UBUNTU_V10_UNIFIED_MATERIALIZATION_INTAKE_RECEIPT.json"
$receipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

$hashRows = @(
    [pscustomobject]@{
        file = $FrozenManifest
        bytes = (Get-Item -LiteralPath $FrozenManifest).Length
        sha256 = $manifestHash
    },
    [pscustomobject]@{
        file = $ledgerPath
        bytes = (Get-Item -LiteralPath $ledgerPath).Length
        sha256 = $ledgerHash
    },
    [pscustomobject]@{
        file = $cleanupPath
        bytes = (Get-Item -LiteralPath $cleanupPath).Length
        sha256 = $cleanupHash
    },
    [pscustomobject]@{
        file = $receiptPath
        bytes = (Get-Item -LiteralPath $receiptPath).Length
        sha256 = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
)

$hashPath = Join-Path $EvidenceRoot "UBUNTU_V10_UNIFIED_MATERIALIZATION_INTAKE_SHA256.csv"
$hashRows | Export-Csv -LiteralPath $hashPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "UBUNTU V10 UNIFIED MATERIALIZATION INTAKE: PASS"
Write-Host "Frozen pool: 19 = 10 PRIMARY + 9 RESERVE"
Write-Host "Host intake layout: ONE DIRECTORY FOR ALL 19"
Write-Host "Host intake root: $UnifiedIntake"
Write-Host "Guest materialization root: /opt/RansomLab/MalwareStaging/P5G/V10/Samples"
Write-Host "Removed empty legacy per-family folders: $($removedEmpty.Count)"
Write-Host "Preserved non-empty legacy folders: $($preservedNonEmpty.Count)"
Write-Host "Old R4 baseline preservation: REQUIRED"
Write-Host "Re-ranking after outcomes: NOT ALLOWED"
Write-Host "Official run slots consumed: 0"
Write-Host ""
Write-Host "Ledger: $ledgerPath"
Write-Host "Receipt: $receiptPath"
Write-Host "Evidence hashes: $hashPath"
