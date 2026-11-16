[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CaptureDir,
    [Parameter(Mandatory=$true)][string]$WorkloadPrepareReceipt,
    [Parameter(Mandatory=$true)][string]$WorkloadRunReceipt,
    [Parameter(Mandatory=$true)][string]$OutputZip,
    [Parameter(Mandatory=$true)][string]$PackReceiptPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{16}$')][string]$AttemptID
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Assert-True([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
function SHA([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Json([string]$Path,[object]$Object){
    $d=Split-Path -Parent $Path
    if(-not(Test-Path $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null}
    [IO.File]::WriteAllText($Path,(($Object|ConvertTo-Json -Depth 16)+"`r`n"),(New-Object Text.UTF8Encoding($false)))
}
$sw=[Diagnostics.Stopwatch]::StartNew()
# V4: raw Procmon PML is the immutable file-telemetry authority.
# Full PML->CSV materialization is intentionally deferred to offline normalization to avoid
# spending many minutes per live run duplicating a derived representation.
$items=@(
    @{Path=(Join-Path $CaptureDir 'capture.pml');Name='capture.pml'},
    @{Path=(Join-Path $CaptureDir 'sysmon_process_tree.csv');Name='sysmon_process_tree.csv'},
    @{Path=(Join-Path $CaptureDir 'prepare_receipt.json');Name='telemetry_prepare_receipt.json'},
    @{Path=(Join-Path $CaptureDir 'capture_receipt.json');Name='telemetry_capture_receipt.json'},
    @{Path=$WorkloadPrepareReceipt;Name='workload_prepare_receipt.json'},
    @{Path=$WorkloadRunReceipt;Name='workload_run_receipt.json'}
)
foreach($i in $items){
    Assert-True (Test-Path -LiteralPath $i.Path -PathType Leaf) ('PACK_INPUT_MISSING:'+$i.Path)
    Assert-True ((Get-Item -LiteralPath $i.Path).Length -gt 0) ('PACK_INPUT_EMPTY:'+$i.Path)
}
$manifest=[ordered]@{
    schema_version='2.0';gate='BENIGN_QUAL_GUEST_ARCHIVE_MANIFEST';AttemptID=$AttemptID
    raw_procmon_pml_preserved=$true;derived_full_csv_included=$false
    process_tree_proof='sysmon_process_tree.csv'
    compression_level='Fastest'
    files=@();timestamp=[DateTime]::UtcNow.ToString('o')
}
foreach($i in $items){
    $fi=Get-Item -LiteralPath $i.Path
    $manifest.files+=[ordered]@{name=$i.Name;sha256=(SHA $i.Path);bytes=[int64]$fi.Length}
}
$manifestPath=Join-Path $CaptureDir 'archive_manifest.json'
Write-Json $manifestPath $manifest
$items+=@(@{Path=$manifestPath;Name='archive_manifest.json'})
if(Test-Path -LiteralPath $OutputZip){Remove-Item -LiteralPath $OutputZip -Force}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[IO.Compression.ZipFile]::Open($OutputZip,[IO.Compression.ZipArchiveMode]::Create)
try{
    foreach($i in $items){
        $entry=$zip.CreateEntry($i.Name,[IO.Compression.CompressionLevel]::Fastest)
        $in=[IO.File]::OpenRead($i.Path)
        $out=$entry.Open()
        try{$in.CopyTo($out,1048576)}finally{$out.Dispose();$in.Dispose()}
    }
}finally{$zip.Dispose()}
Assert-True (Test-Path -LiteralPath $OutputZip -PathType Leaf) 'ARCHIVE_NOT_CREATED'
$z=Get-Item -LiteralPath $OutputZip
$sw.Stop()
$receipt=[ordered]@{
    schema_version='2.0';gate='BENIGN_QUAL_GUEST_PACK';status='PASS';AttemptID=$AttemptID
    archive_path=$OutputZip;archive_sha256=(SHA $OutputZip);archive_bytes=[int64]$z.Length
    included_files=@($items|ForEach-Object{$_.Name})
    raw_procmon_pml_preserved=$true;derived_full_csv_included=$false
    compressed_only_bulk_telemetry_on_host=$true;compression_level='Fastest'
    pack_elapsed_seconds=[Math]::Round($sw.Elapsed.TotalSeconds,3)
    timestamp=[DateTime]::UtcNow.ToString('o')
}
Write-Json $PackReceiptPath $receipt
Write-Host ('BENIGN_GUEST_PACK=PASS BYTES='+$z.Length+' PACK_SECONDS='+$receipt.pack_elapsed_seconds+' SHA256='+$receipt.archive_sha256)
