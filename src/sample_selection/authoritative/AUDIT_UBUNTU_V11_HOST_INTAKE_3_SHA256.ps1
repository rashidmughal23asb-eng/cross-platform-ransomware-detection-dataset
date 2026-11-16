$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"

$FrozenManifest = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V11_EXTENSION_20261111\UBUNTU_V11_FRESH_FAMILY_SELECTION_MANIFEST.csv"

$IntakeRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V11_EXTENSION_INTAKE_20261111\host_archive_intake_all3"

$OutRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V11_EXTENSION_INTAKE_20261111\evidence"
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

if(-not(Test-Path -LiteralPath $FrozenManifest -PathType Leaf)){
    throw "Frozen manifest missing: $FrozenManifest"
}
if(-not(Test-Path -LiteralPath $IntakeRoot -PathType Container)){
    throw "Unified intake root missing: $IntakeRoot"
}

$rows = @(Import-Csv -LiteralPath $FrozenManifest)
if($rows.Count -lt 1){ throw "Frozen manifest must contain at least one row." }

$expected = @{}
foreach($r in $rows){
    $sha = ([string]$r.sha256).Trim().ToLowerInvariant()
    if($sha -notmatch '^[0-9a-f]{64}$'){
        throw "Invalid SHA-256 in frozen manifest: $sha"
    }

    if($expected.ContainsKey($sha)){
        throw "Duplicate SHA-256 in frozen manifest: $sha"
    }

    $expected[$sha] = [pscustomobject]@{
        frozen_rank = [int]$r.frozen_rank
        role = ([string]$r.role).Trim()
        family = ([string]$r.family).Trim()
    }
}

# Safe even when intake is empty.
$files = @(
    Get-ChildItem -LiteralPath $IntakeRoot -File -Recurse -ErrorAction Stop
)

$observed = @{}
$unexpected = @()

foreach($f in $files){
    $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()

    if($expected.ContainsKey($sha)){
        if(-not $observed.ContainsKey($sha)){
            $observed[$sha] = New-Object System.Collections.Generic.List[string]
        }
        [void]$observed[$sha].Add($f.FullName)
    } else {
        $unexpected += [pscustomobject]@{
            file = $f.FullName
            bytes = $f.Length
            sha256 = $sha
            disposition = "UNEXPECTED_HASH_NOT_IN_FROZEN_V10_SET"
        }
    }
}

$audit = @()
$matchedCount = 0
$duplicateMatchCount = 0

foreach($sha in ($expected.Keys | Sort-Object { $expected[$_].frozen_rank })){
    $meta = $expected[$sha]

    # Robust under StrictMode for zero/one/many matches.
    $paths = @()
    if($observed.ContainsKey($sha)){
        foreach($p in $observed[$sha]){
            $paths += [string]$p
        }
    }
    $pathCount = @($paths).Count

    if($pathCount -eq 0){
        $status = "MISSING"
    }
    elseif($pathCount -eq 1){
        $matchedCount++
        $status = "PASS"
    }
    else{
        $matchedCount++
        $duplicateMatchCount++
        $status = "PASS_DUPLICATE_PRESENT"
    }

    $audit += [pscustomobject]@{
        frozen_rank = $meta.frozen_rank
        role = $meta.role
        family = $meta.family
        expected_sha256 = $sha
        status = $status
        matching_file_count = $pathCount
        matching_paths = (@($paths) -join " | ")
    }
}

$auditPath = Join-Path $OutRoot "UBUNTU_V11_HOST_INTAKE_3_SHA256_AUDIT.csv"
$unexpectedPath = Join-Path $OutRoot "UBUNTU_V10_HOST_INTAKE_UNEXPECTED_FILES.csv"

$audit | Export-Csv -LiteralPath $auditPath -NoTypeInformation -Encoding UTF8

# Always create the unexpected-file CSV with a stable schema, even when empty.
if(@($unexpected).Count -gt 0){
    $unexpected | Export-Csv -LiteralPath $unexpectedPath -NoTypeInformation -Encoding UTF8
} else {
    '"file","bytes","sha256","disposition"' | Set-Content -LiteralPath $unexpectedPath -Encoding UTF8
}

$missing = @($audit | Where-Object { $_.status -eq "MISSING" })
$pass19 = ($matchedCount -eq $expected.Count -and $missing.Count -eq 0)

$status = if($pass19){
    if(@($unexpected).Count -eq 0 -and $duplicateMatchCount -eq 0){
        "PASS_EXACT_READY"
    } else {
        "PASS_PRESENT_REVIEW_EXTRAS"
    }
} else {
    "PENDING_NOT_ALL_PRESENT"
}

$receipt = [ordered]@{
    schema_version = "1.1"
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
    status = $status
    frozen_expected_count = $expected.Count
    exact_expected_hashes_present = $matchedCount
    missing_count = $missing.Count
    duplicate_expected_hash_count = $duplicateMatchCount
    unexpected_file_count = @($unexpected).Count
    total_files_in_intake = $files.Count
    intake_root = $IntakeRoot
    frozen_manifest = $FrozenManifest
    audit_csv = $auditPath
    unexpected_csv = $unexpectedPath
    ready_for_next_materialization_gate = ($status -eq "PASS_EXACT_READY")
    official_run_slot_consumed = $false
}

$receiptPath = Join-Path $OutRoot "UBUNTU_V11_HOST_INTAKE_3_SHA256_AUDIT_RECEIPT.json"
$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

$hashRows = @(
    $FrozenManifest,
    $auditPath,
    $unexpectedPath,
    $receiptPath
) | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object {
    [pscustomobject]@{
        file = $_
        bytes = (Get-Item -LiteralPath $_).Length
        sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$hashPath = Join-Path $OutRoot "UBUNTU_V11_HOST_INTAKE_AUDIT_EVIDENCE_SHA256.csv"
$hashRows | Export-Csv -LiteralPath $hashPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "UBUNTU V11 HOST INTAKE SHA-256 AUDIT: $status"
Write-Host "Files currently in intake: $($files.Count)"
Write-Host "Expected frozen samples: $($expected.Count)"
Write-Host "Exact expected hashes present: $matchedCount"
Write-Host "Missing: $($missing.Count)"
Write-Host "Duplicate expected hashes: $duplicateMatchCount"
Write-Host "Unexpected files: $(@($unexpected).Count)"
Write-Host ""
Write-Host "Audit: $auditPath"
Write-Host "Receipt: $receiptPath"
Write-Host "Evidence hashes: $hashPath"

if($status -eq "PASS_EXACT_READY"){ exit 0 }
exit 2
