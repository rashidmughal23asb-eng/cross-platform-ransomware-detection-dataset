[CmdletBinding()]
param(
    [ValidateSet('WINDOWS','UBUNTU')][string]$Platform,
    [string]$CampaignRoot = 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_90Runs'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ManifestPath = Join-Path $CampaignRoot '01_SHARED\manifests\BENIGN_60_RUN_MANIFEST.csv'
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw 'MANIFEST_MISSING' }
$ManifestPlatform = if ($Platform -ceq 'WINDOWS') { 'Windows' } else { 'Ubuntu' }
$Rows = @(Import-Csv -LiteralPath $ManifestPath | Where-Object platform -ceq $ManifestPlatform)
$Ambiguous = @($Rows | Where-Object status -ceq 'RUNNING')
if ($Ambiguous.Count -gt 0) { throw ('AMBIGUOUS_RUNNING_ROWS:' + (($Ambiguous.run_id) -join ',')) }
$Next = @($Rows | Where-Object status -ceq 'PENDING' | Select-Object -First 1)
if ($Next.Count -eq 0) {
    Write-Host ('NO_PENDING_' + $Platform + '_RUNS') -ForegroundColor Green
    exit 0
}
$Next[0] | ConvertTo-Json -Depth 5
